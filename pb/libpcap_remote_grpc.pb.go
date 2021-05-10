// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// PcapRemoteServiceClient is the client API for PcapRemoteService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PcapRemoteServiceClient interface {
	ListInterfaces(ctx context.Context, in *ListInterfacesRequest, opts ...grpc.CallOption) (*ListInterfacesReply, error)
}

type pcapRemoteServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPcapRemoteServiceClient(cc grpc.ClientConnInterface) PcapRemoteServiceClient {
	return &pcapRemoteServiceClient{cc}
}

func (c *pcapRemoteServiceClient) ListInterfaces(ctx context.Context, in *ListInterfacesRequest, opts ...grpc.CallOption) (*ListInterfacesReply, error) {
	out := new(ListInterfacesReply)
	err := c.cc.Invoke(ctx, "/pcap_remote.PcapRemoteService/ListInterfaces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PcapRemoteServiceServer is the server API for PcapRemoteService service.
// All implementations must embed UnimplementedPcapRemoteServiceServer
// for forward compatibility
type PcapRemoteServiceServer interface {
	ListInterfaces(context.Context, *ListInterfacesRequest) (*ListInterfacesReply, error)
	mustEmbedUnimplementedPcapRemoteServiceServer()
}

// UnimplementedPcapRemoteServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPcapRemoteServiceServer struct {
}

func (UnimplementedPcapRemoteServiceServer) ListInterfaces(context.Context, *ListInterfacesRequest) (*ListInterfacesReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListInterfaces not implemented")
}
func (UnimplementedPcapRemoteServiceServer) mustEmbedUnimplementedPcapRemoteServiceServer() {}

// UnsafePcapRemoteServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PcapRemoteServiceServer will
// result in compilation errors.
type UnsafePcapRemoteServiceServer interface {
	mustEmbedUnimplementedPcapRemoteServiceServer()
}

func RegisterPcapRemoteServiceServer(s grpc.ServiceRegistrar, srv PcapRemoteServiceServer) {
	s.RegisterService(&PcapRemoteService_ServiceDesc, srv)
}

func _PcapRemoteService_ListInterfaces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListInterfacesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PcapRemoteServiceServer).ListInterfaces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pcap_remote.PcapRemoteService/ListInterfaces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PcapRemoteServiceServer).ListInterfaces(ctx, req.(*ListInterfacesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PcapRemoteService_ServiceDesc is the grpc.ServiceDesc for PcapRemoteService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PcapRemoteService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pcap_remote.PcapRemoteService",
	HandlerType: (*PcapRemoteServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListInterfaces",
			Handler:    _PcapRemoteService_ListInterfaces_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "libpcap_remote.proto",
}
