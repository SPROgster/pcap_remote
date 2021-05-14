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
	ListInterfaces(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*ListInterfacesReply, error)
	StartCapture(ctx context.Context, in *StartCaptureRequest, opts ...grpc.CallOption) (PcapRemoteService_StartCaptureClient, error)
	StopCapture(ctx context.Context, in *StopCaptureRequest, opts ...grpc.CallOption) (*Empty, error)
}

type pcapRemoteServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPcapRemoteServiceClient(cc grpc.ClientConnInterface) PcapRemoteServiceClient {
	return &pcapRemoteServiceClient{cc}
}

func (c *pcapRemoteServiceClient) ListInterfaces(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*ListInterfacesReply, error) {
	out := new(ListInterfacesReply)
	err := c.cc.Invoke(ctx, "/pcap_remote.PcapRemoteService/ListInterfaces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pcapRemoteServiceClient) StartCapture(ctx context.Context, in *StartCaptureRequest, opts ...grpc.CallOption) (PcapRemoteService_StartCaptureClient, error) {
	stream, err := c.cc.NewStream(ctx, &PcapRemoteService_ServiceDesc.Streams[0], "/pcap_remote.PcapRemoteService/DoCapture", opts...)
	if err != nil {
		return nil, err
	}
	x := &pcapRemoteServiceStartCaptureClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type PcapRemoteService_StartCaptureClient interface {
	Recv() (*Packet, error)
	grpc.ClientStream
}

type pcapRemoteServiceStartCaptureClient struct {
	grpc.ClientStream
}

func (x *pcapRemoteServiceStartCaptureClient) Recv() (*Packet, error) {
	m := new(Packet)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *pcapRemoteServiceClient) StopCapture(ctx context.Context, in *StopCaptureRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/pcap_remote.PcapRemoteService/StopCapture", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PcapRemoteServiceServer is the server API for PcapRemoteService service.
// All implementations must embed UnimplementedPcapRemoteServiceServer
// for forward compatibility
type PcapRemoteServiceServer interface {
	ListInterfaces(context.Context, *Empty) (*ListInterfacesReply, error)
	StartCapture(*StartCaptureRequest, PcapRemoteService_StartCaptureServer) error
	StopCapture(context.Context, *StopCaptureRequest) (*Empty, error)
	mustEmbedUnimplementedPcapRemoteServiceServer()
}

// UnimplementedPcapRemoteServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPcapRemoteServiceServer struct {
}

func (UnimplementedPcapRemoteServiceServer) ListInterfaces(context.Context, *Empty) (*ListInterfacesReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListInterfaces not implemented")
}
func (UnimplementedPcapRemoteServiceServer) StartCapture(*StartCaptureRequest, PcapRemoteService_StartCaptureServer) error {
	return status.Errorf(codes.Unimplemented, "method DoCapture not implemented")
}
func (UnimplementedPcapRemoteServiceServer) StopCapture(context.Context, *StopCaptureRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopCapture not implemented")
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
	in := new(Empty)
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
		return srv.(PcapRemoteServiceServer).ListInterfaces(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PcapRemoteService_StartCapture_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StartCaptureRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PcapRemoteServiceServer).StartCapture(m, &pcapRemoteServiceStartCaptureServer{stream})
}

type PcapRemoteService_StartCaptureServer interface {
	Send(*Packet) error
	grpc.ServerStream
}

type pcapRemoteServiceStartCaptureServer struct {
	grpc.ServerStream
}

func (x *pcapRemoteServiceStartCaptureServer) Send(m *Packet) error {
	return x.ServerStream.SendMsg(m)
}

func _PcapRemoteService_StopCapture_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopCaptureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PcapRemoteServiceServer).StopCapture(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pcap_remote.PcapRemoteService/StopCapture",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PcapRemoteServiceServer).StopCapture(ctx, req.(*StopCaptureRequest))
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
		{
			MethodName: "StopCapture",
			Handler:    _PcapRemoteService_StopCapture_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "DoCapture",
			Handler:       _PcapRemoteService_StartCapture_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "pb/libpcap_remote.proto",
}
