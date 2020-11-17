package pbftlinear

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/joe-zxh/pbftlinear/data"
	"github.com/joe-zxh/pbftlinear/util"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/joe-zxh/pbftlinear/config"
	"github.com/joe-zxh/pbftlinear/consensus"
	"github.com/joe-zxh/pbftlinear/internal/logging"
	"github.com/joe-zxh/pbftlinear/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var logger *log.Logger

func init() {
	logger = logging.GetLogger()
}

// PBFTLinear is a thing
type PBFTLinear struct {
	*consensus.PBFTLinearCore
	proto.UnimplementedPBFTLinearServer

	tls bool

	nodes map[config.ReplicaID]*proto.PBFTLinearClient
	conns map[config.ReplicaID]*grpc.ClientConn

	server *pbftLinearServer

	closeOnce      sync.Once
	connectTimeout time.Duration
}

//New creates a new backend object.
func New(conf *config.ReplicaConfig, tls bool, connectTimeout, qcTimeout time.Duration) *PBFTLinear {
	pbftlinear := &PBFTLinear{
		PBFTLinearCore: consensus.New(conf),
		nodes:          make(map[config.ReplicaID]*proto.PBFTLinearClient),
		conns:          make(map[config.ReplicaID]*grpc.ClientConn),
		connectTimeout: connectTimeout,
	}
	return pbftlinear
}

//Start starts the server and client
func (pbftlinear *PBFTLinear) Start() error {
	addr := pbftlinear.Config.Replicas[pbftlinear.Config.ID].Address
	err := pbftlinear.startServer(addr)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Server: %w", err)
	}
	err = pbftlinear.startClient(pbftlinear.connectTimeout)
	if err != nil {
		return fmt.Errorf("Failed to start GRPC Clients: %w", err)
	}
	return nil
}

// 作为rpc的client端，调用其他hsserver的rpc。
func (pbftlinear *PBFTLinear) startClient(connectTimeout time.Duration) error {

	grpcOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}

	if pbftlinear.tls {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pbftlinear.Config.CertPool, "")))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	for rid, replica := range pbftlinear.Config.Replicas {
		if replica.ID != pbftlinear.Config.ID {
			conn, err := grpc.Dial(replica.Address, grpcOpts...)
			if err != nil {
				log.Fatalf("connect error: %v", err)
				conn.Close()
			} else {
				pbftlinear.conns[rid] = conn
				c := proto.NewPBFTLinearClient(conn)
				pbftlinear.nodes[rid] = &c
			}
		}
	}

	return nil
}

// startServer runs a new instance of pbftLinearServer
func (pbftlinear *PBFTLinear) startServer(port string) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("Failed to listen to port %s: %w", port, err)
	}

	grpcServerOpts := []grpc.ServerOption{}

	if pbftlinear.tls {
		grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewServerTLSFromCert(pbftlinear.Config.Cert)))
	}

	pbftlinear.server = newPBFTLinearServer(pbftlinear) // todo: 实现preprepare、prepare、commit

	s := grpc.NewServer(grpcServerOpts...)
	proto.RegisterPBFTLinearServer(s, pbftlinear.server)

	go s.Serve(lis)
	return nil
}

// Close closes all connections made by the PBFTLinear instance
func (pbftlinear *PBFTLinear) Close() {
	pbftlinear.closeOnce.Do(func() {
		pbftlinear.PBFTLinearCore.Close()
		for _, conn := range pbftlinear.conns { // close clients connections
			conn.Close()
		}
	})
}

// 这个server是面向 集群内部的。
type pbftLinearServer struct {
	*PBFTLinear

	mut     sync.RWMutex
	clients map[context.Context]config.ReplicaID
}

func (pbftlinear *PBFTLinear) Propose(timeout bool) {
	dPP := pbftlinear.CreateProposal(timeout)
	if dPP == nil {
		return
	}

	// leader先处理自己的entry的pp 以及 prepare的签名
	pbftlinear.Mut.Lock()
	ent := pbftlinear.GetEntry(data.EntryID{V: dPP.View, N: dPP.Seq})
	pbftlinear.Mut.Unlock()

	ent.Mut.Lock()
	if ent.PP != nil {
		panic(`leader: ent.PP != nil`)
	}
	ent.PP = dPP

	if ent.PreparedCert != nil {
		panic(`leader: ent.PreparedCert != nil`)
	}
	qc := &data.QuorumCert{
		Sigs:       make(map[config.ReplicaID]data.PartialSig),
		SigContent: ent.GetPrepareHash(),
	}
	ent.PreparedCert = qc
	ent.Mut.Unlock()

	go func() { // 签名比较耗时，所以用goroutine来进行
		ps, err := pbftlinear.SigCache.CreatePartialSig(pbftlinear.Config.ID, pbftlinear.Config.PrivateKey, qc.SigContent.ToSlice())
		if err != nil {
			panic(err)
		}
		ent.Mut.Lock()
		ent.PreparedCert.Sigs[pbftlinear.Config.ID] = *ps
		ent.Mut.Unlock()
	}()

	pPP := proto.PP2Proto(dPP)
	pbftlinear.BroadcastPrePrepareRequest(pPP, ent)
}

func (pbftlinear *PBFTLinear) BroadcastPrePrepareRequest(pPP *proto.PrePrepareArgs, ent *data.Entry) {
	logger.Printf("[B/PrePrepare]: view: %d, seq: %d, (%d commands)\n", pPP.View, pPP.Seq, len(pPP.Commands))

	for rid, client := range pbftlinear.nodes {
		if rid != pbftlinear.Config.ID {
			go func(id config.ReplicaID, cli *proto.PBFTLinearClient) {
				pPPR, err := (*cli).PrePrepare(context.TODO(), pPP)
				if err != nil {
					panic(err)
				}
				dPS := pPPR.Sig.Proto2PartialSig()
				ent.Mut.Lock()
				if ent.Prepared == false &&
					pbftlinear.SigCache.VerifySignature(*dPS, ent.GetPrepareHash()) {
					ent.PreparedCert.Sigs[id] = *dPS
					if len(ent.PreparedCert.Sigs) > int(2*pbftlinear.F) {

						// leader先处理自己的entry的commit的签名
						ent.Prepared = true
						if ent.CommittedCert != nil {
							panic(`leader: ent.CommittedCert != nil`)
						}

						qc := &data.QuorumCert{
							Sigs:       make(map[config.ReplicaID]data.PartialSig),
							SigContent: ent.GetCommitHash(),
						}
						ent.CommittedCert = qc

						// 收拾收拾，准备broadcast prepare
						pP := &proto.PrepareArgs{
							View: ent.PP.View,
							Seq:  ent.PP.Seq,
							QC:   proto.QuorumCertToProto(ent.PreparedCert),
						}
						ent.Mut.Unlock()

						go func() { // 签名比较耗时，所以用goroutine来进行
							ps, err := pbftlinear.SigCache.CreatePartialSig(pbftlinear.Config.ID, pbftlinear.Config.PrivateKey, qc.SigContent.ToSlice())
							if err != nil {
								panic(err)
							}
							ent.Mut.Lock()
							ent.CommittedCert.Sigs[pbftlinear.Config.ID] = *ps
							ent.Mut.Unlock()
						}()

						pbftlinear.BroadcastPrepareRequest(pP, ent)
					} else {
						ent.Mut.Unlock()
					}
				} else {
					ent.Mut.Unlock()
				}
			}(rid, client)
		}
	}
}

func (pbftlinear *PBFTLinear) BroadcastPrepareRequest(pP *proto.PrepareArgs, ent *data.Entry) {
	logger.Printf("[B/Prepare]: view: %d, seq: %d\n", pP.View, pP.Seq)

	for rid, client := range pbftlinear.nodes {

		if rid != pbftlinear.Config.ID {
			go func(id config.ReplicaID, cli *proto.PBFTLinearClient) {
				pPR, err := (*cli).Prepare(context.TODO(), pP)
				if err != nil {
					panic(err)
				}
				dPS := pPR.Sig.Proto2PartialSig()
				ent.Mut.Lock()
				if ent.Committed == false &&
					pbftlinear.SigCache.VerifySignature(*dPS, ent.GetCommitHash()) {
					ent.CommittedCert.Sigs[id] = *dPS
					if len(ent.CommittedCert.Sigs) > int(2*pbftlinear.F) {

						ent.Committed = true

						// 收拾收拾，准备broadcast commit
						pC := &proto.CommitArgs{
							View: ent.PP.View,
							Seq:  ent.PP.Seq,
							QC:   proto.QuorumCertToProto(ent.CommittedCert),
						}
						pbftlinear.BroadcastCommitRequest(pC)

						// 对于leader来说，pp一定存在的，所以不需要先判断是否为nil
						elem := &util.PQElem{
							Pri: int(ent.PP.Seq),
							C:   ent.PP.Commands,
						}
						ent.Mut.Unlock()
						go pbftlinear.ApplyCommands(elem)

					} else {
						ent.Mut.Unlock()
					}
				} else {
					ent.Mut.Unlock()
				}

			}(rid, client)
		}
	}
}

func (pbftlinear *PBFTLinear) BroadcastCommitRequest(pC *proto.CommitArgs) {
	logger.Printf("[B/Commit]: view: %d, seq: %d\n", pC.View, pC.Seq)

	for rid, client := range pbftlinear.nodes {
		if rid != pbftlinear.Config.ID {
			go func(id config.ReplicaID, cli *proto.PBFTLinearClient) {
				_, err := (*cli).Commit(context.TODO(), pC)
				if err != nil {
					panic(err)
				}
			}(rid, client)
		}
	}
}

func (pbftlinear *PBFTLinear) PrePrepare(_ context.Context, pPP *proto.PrePrepareArgs) (*proto.PrePrepareReply, error) {

	logger.Printf("PrePrepare: view:%d, seq:%d\n", pPP.View, pPP.Seq)

	dPP := pPP.Proto2PP()

	pbftlinear.Mut.Lock()

	if !pbftlinear.Changing && pbftlinear.View == dPP.View {

		ent := pbftlinear.GetEntry(data.EntryID{V: dPP.View, N: dPP.Seq})
		pbftlinear.Mut.Unlock()

		ent.Mut.Lock()
		if ent.Digest == nil {
			ent.PP = dPP
			ps, err := pbftlinear.SigCache.CreatePartialSig(pbftlinear.Config.ID, pbftlinear.Config.PrivateKey, ent.GetPrepareHash().ToSlice())
			if err != nil {
				panic(err)
			}
			if ent.Committed { // 有可能已经commit了，但是PP还没收到
				elem := &util.PQElem{
					Pri: int(ent.PP.Seq),
					C:   ent.PP.Commands,
				}
				go pbftlinear.ApplyCommands(elem)
			}

			ent.Mut.Unlock()

			ppReply := &proto.PrePrepareReply{
				Sig: proto.PartialSig2Proto(ps),
			}
			return ppReply, nil
		} else {
			ent.Mut.Unlock()
			fmt.Println(`多个具有相同seq的preprepare`)
			return nil, errors.New(`多个具有相同seq的preprepare`)
		}

	} else {
		pbftlinear.Mut.Unlock()
		return nil, errors.New(`正在view change 或者 view不匹配`)
	}
}

func (pbftlinear *PBFTLinear) Prepare(_ context.Context, pP *proto.PrepareArgs) (*proto.PrepareReply, error) {
	logger.Printf("Receive Prepare: seq: %d, view: %d\n", pP.Seq, pP.View)

	pbftlinear.Mut.Lock()
	if !pbftlinear.Changing && pbftlinear.View == pP.View {
		ent := pbftlinear.GetEntry(data.EntryID{pP.View, pP.Seq})
		pbftlinear.Mut.Unlock()

		ent.Mut.Lock()

		if ent.Prepared == true {
			panic(`already prepared...`)
		}

		// 检查qc
		dQc := pP.QC.Proto2QuorumCert()
		if !pbftlinear.SigCache.VerifyQuorumCert(dQc) {
			logger.Println("Prepared QC not verified!: ", dQc)
			return nil, errors.New(`Prepared QC not verified!`)
		}

		if ent.PreparedCert != nil {
			panic(`follower: ent.PreparedCert != nil`)
		}
		ent.PreparedCert = &data.QuorumCert{
			Sigs:       dQc.Sigs,
			SigContent: dQc.SigContent,
		}
		ent.Prepared = true
		ent.PrepareHash = &dQc.SigContent // 这里应该做检查的，如果先收到PP，PHash需要相等。PP那里，如果有PHash和CHash需要检查是否相等。这里简化了。

		ps, err := pbftlinear.SigCache.CreatePartialSig(pbftlinear.Config.ID, pbftlinear.Config.PrivateKey, ent.GetCommitHash().ToSlice())
		if err != nil {
			panic(err)
		}
		ent.Mut.Unlock()

		pPR := &proto.PrepareReply{Sig: proto.PartialSig2Proto(ps)}
		return pPR, nil

	} else {
		pbftlinear.Mut.Unlock()
	}
	return nil, nil
}

func (pbftlinear *PBFTLinear) Commit(_ context.Context, pC *proto.CommitArgs) (*empty.Empty, error) {
	logger.Printf("Receive Commit: seq: %d, view: %d\n", pC.Seq, pC.View)
	pbftlinear.Mut.Lock()
	if !pbftlinear.Changing && pbftlinear.View == pC.View {
		ent := pbftlinear.GetEntry(data.EntryID{pC.View, pC.Seq})
		pbftlinear.Mut.Unlock()

		ent.Mut.Lock()

		if ent.Committed == true {
			panic(`already committed...`)
		}

		// 检查qc
		dQc := pC.QC.Proto2QuorumCert()
		if !pbftlinear.SigCache.VerifyQuorumCert(dQc) {
			logger.Println("Commit QC not verified!: ", dQc)
			return &empty.Empty{}, errors.New(`Commit QC not verified!`)
		}

		if ent.CommittedCert != nil {
			panic(`follower: ent.CommittedCert != nil`)
		}
		ent.CommittedCert = &data.QuorumCert{
			Sigs:       dQc.Sigs,
			SigContent: dQc.SigContent,
		}
		ent.Committed = true
		ent.CommitHash = &dQc.SigContent // 这里应该做检查的，如果先收到P，CHash需要相等。PP那里，如果有PHash和CHash需要检查是否相等。这里简化了。

		if ent.PP != nil {
			elem := &util.PQElem{
				Pri: int(ent.PP.Seq),
				C:   ent.PP.Commands,
			}
			ent.Mut.Unlock()
			go pbftlinear.ApplyCommands(elem)
		}else{
			ent.Mut.Unlock()
		}

		return &empty.Empty{}, nil
	} else {
		pbftlinear.Mut.Unlock()
	}
	return &empty.Empty{}, nil
}

func (pbftlinear *PBFTLinear) ApplyCommands(elem *util.PQElem) {
	pbftlinear.Mut.Lock()
	inserted := pbftlinear.ApplyQueue.Insert(*elem)
	if !inserted {
		panic("Already insert some request with same sequence")
	}

	for i, sz := 0, pbftlinear.ApplyQueue.Length(); i < sz; i++ { // commit需要按global seq的顺序
		m, err := pbftlinear.ApplyQueue.GetMin()
		if err != nil {
			break
		}
		if int(pbftlinear.Apply+1) == m.Pri {
			pbftlinear.Apply++
			cmds, ok := m.C.([]data.Command)
			if ok {
				pbftlinear.Exec <- cmds
			}
			pbftlinear.ApplyQueue.ExtractMin()

		} else if int(pbftlinear.Apply+1) > m.Pri {
			panic("This should already done")
		} else {
			break
		}
	}
	pbftlinear.Mut.Unlock()
}

func (pbftlinear *PBFTLinear) ApplyCommands1() {
	for i, sz := 0, pbftlinear.ApplyQueue.Length(); i < sz; i++ { // commit需要按global seq的顺序
		m, err := pbftlinear.ApplyQueue.GetMin()
		if err != nil {
			break
		}
		if int(pbftlinear.Apply+1) == m.Pri {
			pbftlinear.Apply++
			cmds, ok := m.C.([]data.Command)
			if ok {
				pbftlinear.Exec <- cmds
			}
			pbftlinear.ApplyQueue.ExtractMin()

		} else if int(pbftlinear.Apply+1) > m.Pri {
			panic("This should already done")
		} else {
			break
		}
	}
}

func newPBFTLinearServer(pbftlinear *PBFTLinear) *pbftLinearServer {
	pbftSrv := &pbftLinearServer{
		PBFTLinear: pbftlinear,
		clients:    make(map[context.Context]config.ReplicaID),
	}
	return pbftSrv
}

func (pbftlinear *pbftLinearServer) getClientID(ctx context.Context) (config.ReplicaID, error) {
	pbftlinear.mut.RLock()
	// fast path for known stream
	if id, ok := pbftlinear.clients[ctx]; ok {
		pbftlinear.mut.RUnlock()
		return id, nil
	}

	pbftlinear.mut.RUnlock()
	pbftlinear.mut.Lock()
	defer pbftlinear.mut.Unlock()

	// cleanup finished streams
	for ctx := range pbftlinear.clients {
		if ctx.Err() != nil {
			delete(pbftlinear.clients, ctx)
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, fmt.Errorf("getClientID: metadata not available")
	}

	v := md.Get("id")
	if len(v) < 1 {
		return 0, fmt.Errorf("getClientID: id field not present")
	}

	id, err := strconv.Atoi(v[0])
	if err != nil {
		return 0, fmt.Errorf("getClientID: cannot parse ID field: %w", err)
	}

	info, ok := pbftlinear.Config.Replicas[config.ReplicaID(id)]
	if !ok {
		return 0, fmt.Errorf("getClientID: could not find info about id '%d'", id)
	}

	v = md.Get("proof")
	if len(v) < 2 {
		return 0, fmt.Errorf("getClientID: No proof found")
	}

	var R, S big.Int
	v0, err := base64.StdEncoding.DecodeString(v[0])
	if err != nil {
		return 0, fmt.Errorf("getClientID: could not decode proof: %v", err)
	}
	v1, err := base64.StdEncoding.DecodeString(v[1])
	if err != nil {
		return 0, fmt.Errorf("getClientID: could not decode proof: %v", err)
	}
	R.SetBytes(v0)
	S.SetBytes(v1)

	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(pbftlinear.Config.ID))
	hash := sha512.Sum512(b[:])

	if !ecdsa.Verify(info.PubKey, hash[:], &R, &S) {
		return 0, fmt.Errorf("Invalid proof")
	}

	pbftlinear.clients[ctx] = config.ReplicaID(id)
	return config.ReplicaID(id), nil
}
