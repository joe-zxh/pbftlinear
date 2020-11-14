package pbftlinear

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/joe-zxh/pbftlinear/util"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/joe-zxh/pbftlinear/config"
	"github.com/joe-zxh/pbftlinear/consensus"
	"github.com/joe-zxh/pbftlinear/data"
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
	tls bool

	nodes map[config.ReplicaID]*proto.Node

	server  *pbftLinearServer
	manager *proto.Manager
	cfg     *proto.Configuration

	closeOnce sync.Once

	connectTimeout time.Duration
}

//New creates a new backend object.
func New(conf *config.ReplicaConfig, tls bool, connectTimeout, qcTimeout time.Duration) *PBFTLinear {
	pbftlinear := &PBFTLinear{
		PBFTLinearCore: consensus.New(conf),
		nodes:          make(map[config.ReplicaID]*proto.Node),
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
	idMapping := make(map[string]uint32, len(pbftlinear.Config.Replicas)-1)
	for _, replica := range pbftlinear.Config.Replicas {
		if replica.ID != pbftlinear.Config.ID {
			idMapping[replica.Address] = uint32(replica.ID)
		}
	}

	// embed own ID to allow other replicas to identify messages from this replica
	md := metadata.New(map[string]string{
		"id": fmt.Sprintf("%d", pbftlinear.Config.ID),
	})

	perNodeMD := func(nid uint32) metadata.MD {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], nid)
		hash := sha512.Sum512(b[:])
		R, S, err := ecdsa.Sign(rand.Reader, pbftlinear.Config.PrivateKey, hash[:])
		if err != nil {
			panic(fmt.Errorf("Could not sign proof for replica %d: %w", nid, err))
		}
		md := metadata.MD{}
		md.Append("proof", base64.StdEncoding.EncodeToString(R.Bytes()), base64.StdEncoding.EncodeToString(S.Bytes()))
		return md
	}

	mgrOpts := []proto.ManagerOption{
		proto.WithDialTimeout(connectTimeout),
		proto.WithNodeMap(idMapping),
		proto.WithMetadata(md),
		proto.WithPerNodeMetadata(perNodeMD),
	}
	grpcOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}

	if pbftlinear.tls {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pbftlinear.Config.CertPool, "")))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithInsecure())
	}

	mgrOpts = append(mgrOpts, proto.WithGrpcDialOptions(grpcOpts...))

	mgr, err := proto.NewManager(mgrOpts...)
	if err != nil {
		return fmt.Errorf("Failed to connect to replicas: %w", err)
	}
	pbftlinear.manager = mgr

	for _, node := range mgr.Nodes() {
		pbftlinear.nodes[config.ReplicaID(node.ID())] = node
	}

	pbftlinear.cfg, err = pbftlinear.manager.NewConfiguration(pbftlinear.manager.NodeIDs(), &struct{}{})
	if err != nil {
		return fmt.Errorf("Failed to create configuration: %w", err)
	}

	return nil
}

// startServer runs a new instance of pbftLinearServer
func (pbftlinear *PBFTLinear) startServer(port string) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		return fmt.Errorf("Failed to listen to port %s: %w", port, err)
	}

	serverOpts := []proto.ServerOption{}
	grpcServerOpts := []grpc.ServerOption{}

	if pbftlinear.tls {
		grpcServerOpts = append(grpcServerOpts, grpc.Creds(credentials.NewServerTLSFromCert(pbftlinear.Config.Cert)))
	}

	serverOpts = append(serverOpts, proto.WithGRPCServerOptions(grpcServerOpts...))

	pbftlinear.server = newPBFTLinearServer(pbftlinear, proto.NewGorumsServer(serverOpts...))
	s := grpc.NewServer()
	pbftlinear.server.RegisterPBFTLinearServer(pbftlinear.server)

	go pbftlinear.server.Serve(lis)
	return nil
}

// Close closes all connections made by the PBFTLinear instance
func (pbftlinear *PBFTLinear) Close() {
	pbftlinear.closeOnce.Do(func() {
		pbftlinear.PBFTLinearCore.Close()
		pbftlinear.manager.Close()
		pbftlinear.server.Stop()
	})
}

// Propose broadcasts a new proposal(Pre-Prepare) to all replicas
func (pbftlinear *PBFTLinear) Propose(timeout bool) {
	pp := pbftlinear.CreateProposal(timeout)
	if pp == nil {
		return
	}
	logger.Printf("[B/PrePrepare]: view: %d, seq: %d, (%d commands)\n", pp.View, pp.Seq, len(pp.Commands))
	protobuf := proto.PP2Proto(pp)

	for i, sz := 1, len(pbftlinear.nodes); i <= sz; i++ {
		go func(id int) {
			var ppReply *proto.PrePrepareReply
			var err error

			ppReply, err = pbftlinear.nodes[config.ReplicaID(i)].PrePrepare(context.Background(), protobuf)
			if err != nil {
				fmt.Printf("PrePrepare RPC error: %v\n", err)
			}
			pbftlinear.handlePPReply(ppReply)
			// fwefawfawf
		}(i)
	}

	// 通过gorums的cfg进行multicast，multicast应该是 不会发送消息给自己的。

	pbftlinear.handlePrePrepare(pp) // leader自己也要处理proposal
}

func (pbftlinear *PBFTLinear) handlePPReply(ppr *proto.PrePrepareReply) {
	// 收集签名，准备发起prepare
}

func (pbftlinear *PBFTLinear) handlePrePrepare(pp *data.PrePrepareArgs) (*proto.PrePrepareReply, error) {
	return nil, nil

	//pbftlinear.PBFTLinearCore.Mut.Lock()
	//
	//if !pbftlinear.Changing && pbftlinear.View == pp.View {
	//
	//	ent := pbftlinear.GetEntry(data.EntryID{V: pp.View, N: pp.Seq})
	//	pbftlinear.PBFTLinearCore.Mut.Unlock()
	//
	//	ent.Mut.Lock()
	//	if ent.Digest == nil {
	//		ent.PP = pp
	//		ent.Hash()
	//		p := &proto.PrepareArgs{
	//			View:   pp.View,
	//			Seq:    pp.Seq,
	//			Digest: ent.Digest.ToSlice(),
	//		}
	//		ent.Mut.Unlock()
	//
	//		logger.Printf("[B/Prepare]: view: %d, seq: %d\n", pp.View, pp.Seq)
	//		pbftlinear.cfg.Prepare(p)
	//		dp := p.Proto2P()
	//		dp.Sender = pbftlinear.ID
	//		pbftlinear.handlePrepare(dp)
	//	} else {
	//		ent.Mut.Unlock()
	//		fmt.Println(`接收到多个具有相同seq的preprepare`)
	//	}
	//
	//} else {
	//	pbftlinear.PBFTLinearCore.Mut.Unlock()
	//}
}

func (pbftlinear *pbftLinearServer) PrePrepare(ctx context.Context, protoPP *proto.PrePrepareArgs) (*proto.PrePrepareReply, error) {
	fmt.Println(`Hi, in PrePrepare GRPC...`)
	dpp := protoPP.Proto2PP()
	id, err := pbftlinear.getClientID(ctx)
	if err != nil {
		logger.Printf("Failed to get client ID: %v", err)
		return nil, err
	}
	if uint32(id) == pbftlinear.Leader { // 只处理来自leader的preprepare
		return pbftlinear.handlePrePrepare(dpp)
	} else {
		return nil, errors.New(`you are not leader, fuck you`)
	}
}

func (pbftlinear *PBFTLinear) handlePrepare(p *data.PrepareArgs) {

	pbftlinear.Mut.Lock()

	if !pbftlinear.Changing && pbftlinear.View == p.View {
		ent := pbftlinear.GetEntry(data.EntryID{p.View, p.Seq})
		pbftlinear.Mut.Unlock()

		ent.Mut.Lock()

		ent.P = append(ent.P, p)
		if ent.PP != nil && !ent.SendCommit && pbftlinear.Prepared(ent) {

			c := &proto.CommitArgs{
				View:   ent.PP.View,
				Seq:    ent.PP.Seq,
				Digest: ent.Digest.ToSlice(),
			}

			ent.SendCommit = true
			ent.Mut.Unlock()

			logger.Printf("[B/Commit]: view: %d, seq: %d\n", p.View, p.Seq)
			pbftlinear.cfg.Commit(c)
			dc := c.Proto2C()
			dc.Sender = pbftlinear.ID
			pbftlinear.handleCommit(dc)
		} else {
			ent.Mut.Unlock()
		}
	} else {
		pbftlinear.Mut.Unlock()
	}
}

func (pbftlinear *pbftLinearServer) Prepare(ctx context.Context, protoP *proto.PrepareArgs) {
	dp := protoP.Proto2P()
	id, err := pbftlinear.getClientID(ctx)
	if err != nil {
		logger.Printf("Failed to get client ID: %v", err)
		return
	}
	dp.Sender = uint32(id)
	pbftlinear.handlePrepare(dp)
}

func (pbftlinear *PBFTLinear) handleCommit(c *data.CommitArgs) {
	pbftlinear.Mut.Lock()

	if !pbftlinear.Changing && pbftlinear.View == c.View {
		ent := pbftlinear.GetEntry(data.EntryID{c.View, c.Seq})
		pbftlinear.Mut.Unlock()

		ent.Mut.Lock()
		ent.C = append(ent.C, c)
		if !ent.Committed && ent.SendCommit && pbftlinear.Committed(ent) {
			logger.Printf("Committed entry: view: %d, seq: %d\n", ent.PP.View, ent.PP.Seq)
			ent.Committed = true

			elem := util.PQElem{
				Pri: int(ent.PP.Seq),
				C:   ent.PP.Commands,
			}
			ent.Mut.Unlock()
			pbftlinear.Mut.Lock()

			inserted := pbftlinear.ApplyQueue.Insert(elem)
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
		} else {
			ent.Mut.Unlock()
		}
	} else {
		pbftlinear.Mut.Unlock()
	}
}

func (pbftlinear *pbftLinearServer) Commit(ctx context.Context, protoC *proto.CommitArgs) {
	dc := protoC.Proto2C()
	id, err := pbftlinear.getClientID(ctx)
	if err != nil {
		logger.Printf("Failed to get client ID: %v", err)
		return
	}
	dc.Sender = uint32(id)
	pbftlinear.handleCommit(dc)
}

// 这个server是面向 集群内部的。
type pbftLinearServer struct {
	proto.UnimplementedPBFTLinearServer
	*proto.GorumsServer
	// maps a stream context to client info
	mut     sync.RWMutex
	clients map[context.Context]config.ReplicaID
}

func newPBFTLinearServer(pbftlinear *PBFTLinear, srv *proto.GorumsServer) *pbftLinearServer {
	pbftSrv := &pbftLinearServer{
		PBFTLinear:   pbftlinear,
		GorumsServer: srv,
		clients:      make(map[context.Context]config.ReplicaID),
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
