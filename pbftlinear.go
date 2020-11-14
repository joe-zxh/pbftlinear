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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	pp := pbftlinear.CreateProposal(timeout)
	if pp == nil {
		return
	}
	logger.Printf("[B/PrePrepare]: view: %d, seq: %d, (%d commands)\n", pp.View, pp.Seq, len(pp.Commands))
	protobuf := proto.PP2Proto(pp)

	for rid, client := range pbftlinear.nodes {
		if rid != pbftlinear.Config.ID {
			(*client).PrePrepare(context.TODO(), protobuf)
		}
	}
}

func (pbftlinear *PBFTLinear) handlePrePrepare(pp *data.PrePrepareArgs) (*proto.PrePrepareReply, error) {

	pbftlinear.PBFTLinearCore.Mut.Lock()

	if !pbftlinear.Changing && pbftlinear.View == pp.View {

		ent := pbftlinear.GetEntry(data.EntryID{V: pp.View, N: pp.Seq})
		pbftlinear.PBFTLinearCore.Mut.Unlock()

		ent.Mut.Lock()
		if ent.Digest == nil {
			ent.PP = pp
			ps, err := pbftlinear.SigCache.CreatePartialSig(pbftlinear.Config.ID, pbftlinear.Config.PrivateKey, ent.Hash().ToSlice())
			if err != nil {
				fmt.Println(err)
				return nil, err
			}

			ppReply := &proto.PrePrepareReply{
				Sig: ps.tofawefawefawf,
			}
			ent.Mut.Unlock()
		} else {
			ent.Mut.Unlock()
			fmt.Println(`多个具有相同seq的preprepare`)
			return nil, errors.New(`多个具有相同seq的preprepare`)
		}

	} else {
		pbftlinear.PBFTLinearCore.Mut.Unlock()
	}
}

func (pbftlinear *PBFTLinear) PrePrepare(context.Context, *proto.PrePrepareArgs) (*proto.PrePrepareReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrePrepare not implemented")
}

func (pbftlinear *PBFTLinear) Prepare(context.Context, *proto.PrepareArgs) (*proto.PrepareReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Prepare not implemented")
}

func (pbftlinear *PBFTLinear) Commit(context.Context, *proto.CommitArgs) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Commit not implemented")
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
