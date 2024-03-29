// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

import (
	context "context"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// PBFTLinearClient is the client API for PBFTLinear service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PBFTLinearClient interface {
	PrePrepare(ctx context.Context, in *PrePrepareArgs, opts ...grpc.CallOption) (*PrePrepareReply, error)
	Prepare(ctx context.Context, in *PrepareArgs, opts ...grpc.CallOption) (*PrepareReply, error)
	Commit(ctx context.Context, in *CommitArgs, opts ...grpc.CallOption) (*empty.Empty, error)
}

type pBFTLinearClient struct {
	cc grpc.ClientConnInterface
}

func NewPBFTLinearClient(cc grpc.ClientConnInterface) PBFTLinearClient {
	return &pBFTLinearClient{cc}
}

func (c *pBFTLinearClient) PrePrepare(ctx context.Context, in *PrePrepareArgs, opts ...grpc.CallOption) (*PrePrepareReply, error) {
	out := new(PrePrepareReply)
	err := c.cc.Invoke(ctx, "/proto.PBFTLinear/PrePrepare", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pBFTLinearClient) Prepare(ctx context.Context, in *PrepareArgs, opts ...grpc.CallOption) (*PrepareReply, error) {
	out := new(PrepareReply)
	err := c.cc.Invoke(ctx, "/proto.PBFTLinear/Prepare", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pBFTLinearClient) Commit(ctx context.Context, in *CommitArgs, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/proto.PBFTLinear/Commit", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PBFTLinearServer is the server API for PBFTLinear service.
// All implementations must embed UnimplementedPBFTLinearServer
// for forward compatibility
type PBFTLinearServer interface {
	PrePrepare(context.Context, *PrePrepareArgs) (*PrePrepareReply, error)
	Prepare(context.Context, *PrepareArgs) (*PrepareReply, error)
	Commit(context.Context, *CommitArgs) (*empty.Empty, error)
	mustEmbedUnimplementedPBFTLinearServer()
}

// UnimplementedPBFTLinearServer must be embedded to have forward compatible implementations.
type UnimplementedPBFTLinearServer struct {
}

func (*UnimplementedPBFTLinearServer) PrePrepare(context.Context, *PrePrepareArgs) (*PrePrepareReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrePrepare not implemented")
}
func (*UnimplementedPBFTLinearServer) Prepare(context.Context, *PrepareArgs) (*PrepareReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Prepare not implemented")
}
func (*UnimplementedPBFTLinearServer) Commit(context.Context, *CommitArgs) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Commit not implemented")
}
func (*UnimplementedPBFTLinearServer) mustEmbedUnimplementedPBFTLinearServer() {}

func RegisterPBFTLinearServer(s *grpc.Server, srv PBFTLinearServer) {
	s.RegisterService(&_PBFTLinear_serviceDesc, srv)
}

func _PBFTLinear_PrePrepare_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PrePrepareArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PBFTLinearServer).PrePrepare(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.PBFTLinear/PrePrepare",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PBFTLinearServer).PrePrepare(ctx, req.(*PrePrepareArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _PBFTLinear_Prepare_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PrepareArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PBFTLinearServer).Prepare(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.PBFTLinear/Prepare",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PBFTLinearServer).Prepare(ctx, req.(*PrepareArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _PBFTLinear_Commit_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CommitArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PBFTLinearServer).Commit(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.PBFTLinear/Commit",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PBFTLinearServer).Commit(ctx, req.(*CommitArgs))
	}
	return interceptor(ctx, in, info, handler)
}

var _PBFTLinear_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.PBFTLinear",
	HandlerType: (*PBFTLinearServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PrePrepare",
			Handler:    _PBFTLinear_PrePrepare_Handler,
		},
		{
			MethodName: "Prepare",
			Handler:    _PBFTLinear_Prepare_Handler,
		},
		{
			MethodName: "Commit",
			Handler:    _PBFTLinear_Commit_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pbftlinear.proto",
}
