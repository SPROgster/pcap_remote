// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pb/libpcap_remote.proto

package pb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Empty struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Empty) Reset()         { *m = Empty{} }
func (m *Empty) String() string { return proto.CompactTextString(m) }
func (*Empty) ProtoMessage()    {}
func (*Empty) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{0}
}

func (m *Empty) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Empty.Unmarshal(m, b)
}
func (m *Empty) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Empty.Marshal(b, m, deterministic)
}
func (m *Empty) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Empty.Merge(m, src)
}
func (m *Empty) XXX_Size() int {
	return xxx_messageInfo_Empty.Size(m)
}
func (m *Empty) XXX_DiscardUnknown() {
	xxx_messageInfo_Empty.DiscardUnknown(m)
}

var xxx_messageInfo_Empty proto.InternalMessageInfo

type ListInterfacesReply struct {
	InterfaceList        map[string]*ListInterfacesReply_Interface `protobuf:"bytes,1,rep,name=interfaceList,proto3" json:"interfaceList,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                                  `json:"-"`
	XXX_unrecognized     []byte                                    `json:"-"`
	XXX_sizecache        int32                                     `json:"-"`
}

func (m *ListInterfacesReply) Reset()         { *m = ListInterfacesReply{} }
func (m *ListInterfacesReply) String() string { return proto.CompactTextString(m) }
func (*ListInterfacesReply) ProtoMessage()    {}
func (*ListInterfacesReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{1}
}

func (m *ListInterfacesReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListInterfacesReply.Unmarshal(m, b)
}
func (m *ListInterfacesReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListInterfacesReply.Marshal(b, m, deterministic)
}
func (m *ListInterfacesReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListInterfacesReply.Merge(m, src)
}
func (m *ListInterfacesReply) XXX_Size() int {
	return xxx_messageInfo_ListInterfacesReply.Size(m)
}
func (m *ListInterfacesReply) XXX_DiscardUnknown() {
	xxx_messageInfo_ListInterfacesReply.DiscardUnknown(m)
}

var xxx_messageInfo_ListInterfacesReply proto.InternalMessageInfo

func (m *ListInterfacesReply) GetInterfaceList() map[string]*ListInterfacesReply_Interface {
	if m != nil {
		return m.InterfaceList
	}
	return nil
}

type ListInterfacesReply_Interface struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Description          string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListInterfacesReply_Interface) Reset()         { *m = ListInterfacesReply_Interface{} }
func (m *ListInterfacesReply_Interface) String() string { return proto.CompactTextString(m) }
func (*ListInterfacesReply_Interface) ProtoMessage()    {}
func (*ListInterfacesReply_Interface) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{1, 1}
}

func (m *ListInterfacesReply_Interface) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListInterfacesReply_Interface.Unmarshal(m, b)
}
func (m *ListInterfacesReply_Interface) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListInterfacesReply_Interface.Marshal(b, m, deterministic)
}
func (m *ListInterfacesReply_Interface) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListInterfacesReply_Interface.Merge(m, src)
}
func (m *ListInterfacesReply_Interface) XXX_Size() int {
	return xxx_messageInfo_ListInterfacesReply_Interface.Size(m)
}
func (m *ListInterfacesReply_Interface) XXX_DiscardUnknown() {
	xxx_messageInfo_ListInterfacesReply_Interface.DiscardUnknown(m)
}

var xxx_messageInfo_ListInterfacesReply_Interface proto.InternalMessageInfo

func (m *ListInterfacesReply_Interface) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ListInterfacesReply_Interface) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

type StartCaptureRequest struct {
	Uuid                 string   `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Device               string   `protobuf:"bytes,2,opt,name=device,proto3" json:"device,omitempty"`
	SnapshotLen          uint32   `protobuf:"varint,3,opt,name=snapshot_len,json=snapshotLen,proto3" json:"snapshot_len,omitempty"`
	Promiscuous          bool     `protobuf:"varint,4,opt,name=promiscuous,proto3" json:"promiscuous,omitempty"`
	PcapFilter           string   `protobuf:"bytes,5,opt,name=pcap_filter,json=pcapFilter,proto3" json:"pcap_filter,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StartCaptureRequest) Reset()         { *m = StartCaptureRequest{} }
func (m *StartCaptureRequest) String() string { return proto.CompactTextString(m) }
func (*StartCaptureRequest) ProtoMessage()    {}
func (*StartCaptureRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{2}
}

func (m *StartCaptureRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StartCaptureRequest.Unmarshal(m, b)
}
func (m *StartCaptureRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StartCaptureRequest.Marshal(b, m, deterministic)
}
func (m *StartCaptureRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StartCaptureRequest.Merge(m, src)
}
func (m *StartCaptureRequest) XXX_Size() int {
	return xxx_messageInfo_StartCaptureRequest.Size(m)
}
func (m *StartCaptureRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StartCaptureRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StartCaptureRequest proto.InternalMessageInfo

func (m *StartCaptureRequest) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

func (m *StartCaptureRequest) GetDevice() string {
	if m != nil {
		return m.Device
	}
	return ""
}

func (m *StartCaptureRequest) GetSnapshotLen() uint32 {
	if m != nil {
		return m.SnapshotLen
	}
	return 0
}

func (m *StartCaptureRequest) GetPromiscuous() bool {
	if m != nil {
		return m.Promiscuous
	}
	return false
}

func (m *StartCaptureRequest) GetPcapFilter() string {
	if m != nil {
		return m.PcapFilter
	}
	return ""
}

type StopCaptureRequest struct {
	Uuid                 string   `protobuf:"bytes,1,opt,name=uuid,proto3" json:"uuid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StopCaptureRequest) Reset()         { *m = StopCaptureRequest{} }
func (m *StopCaptureRequest) String() string { return proto.CompactTextString(m) }
func (*StopCaptureRequest) ProtoMessage()    {}
func (*StopCaptureRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{3}
}

func (m *StopCaptureRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StopCaptureRequest.Unmarshal(m, b)
}
func (m *StopCaptureRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StopCaptureRequest.Marshal(b, m, deterministic)
}
func (m *StopCaptureRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StopCaptureRequest.Merge(m, src)
}
func (m *StopCaptureRequest) XXX_Size() int {
	return xxx_messageInfo_StopCaptureRequest.Size(m)
}
func (m *StopCaptureRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StopCaptureRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StopCaptureRequest proto.InternalMessageInfo

func (m *StopCaptureRequest) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

type Packet struct {
	Ts                   int64    `protobuf:"varint,1,opt,name=ts,proto3" json:"ts,omitempty"`
	Vlan                 uint32   `protobuf:"varint,2,opt,name=vlan,proto3" json:"vlan,omitempty"`
	Packet               []byte   `protobuf:"bytes,3,opt,name=packet,proto3" json:"packet,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Packet) Reset()         { *m = Packet{} }
func (m *Packet) String() string { return proto.CompactTextString(m) }
func (*Packet) ProtoMessage()    {}
func (*Packet) Descriptor() ([]byte, []int) {
	return fileDescriptor_485463ef1761b568, []int{4}
}

func (m *Packet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Packet.Unmarshal(m, b)
}
func (m *Packet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Packet.Marshal(b, m, deterministic)
}
func (m *Packet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Packet.Merge(m, src)
}
func (m *Packet) XXX_Size() int {
	return xxx_messageInfo_Packet.Size(m)
}
func (m *Packet) XXX_DiscardUnknown() {
	xxx_messageInfo_Packet.DiscardUnknown(m)
}

var xxx_messageInfo_Packet proto.InternalMessageInfo

func (m *Packet) GetTs() int64 {
	if m != nil {
		return m.Ts
	}
	return 0
}

func (m *Packet) GetVlan() uint32 {
	if m != nil {
		return m.Vlan
	}
	return 0
}

func (m *Packet) GetPacket() []byte {
	if m != nil {
		return m.Packet
	}
	return nil
}

func init() {
	proto.RegisterType((*Empty)(nil), "pcap_remote.Empty")
	proto.RegisterType((*ListInterfacesReply)(nil), "pcap_remote.ListInterfacesReply")
	proto.RegisterMapType((map[string]*ListInterfacesReply_Interface)(nil), "pcap_remote.ListInterfacesReply.InterfaceListEntry")
	proto.RegisterType((*ListInterfacesReply_Interface)(nil), "pcap_remote.ListInterfacesReply.Interface")
	proto.RegisterType((*StartCaptureRequest)(nil), "pcap_remote.StartCaptureRequest")
	proto.RegisterType((*StopCaptureRequest)(nil), "pcap_remote.StopCaptureRequest")
	proto.RegisterType((*Packet)(nil), "pcap_remote.Packet")
}

func init() { proto.RegisterFile("pb/libpcap_remote.proto", fileDescriptor_485463ef1761b568) }

var fileDescriptor_485463ef1761b568 = []byte{
	// 462 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x53, 0x4d, 0x6f, 0x13, 0x31,
	0x10, 0xad, 0x93, 0x26, 0x90, 0xd9, 0xa4, 0x02, 0x47, 0x82, 0x55, 0x2e, 0x5d, 0xf6, 0xb4, 0x80,
	0x94, 0xa0, 0xe4, 0x82, 0x38, 0xf1, 0xd1, 0x22, 0x22, 0x55, 0x22, 0x72, 0x4e, 0x70, 0xa9, 0xbc,
	0x9b, 0x69, 0x6b, 0x75, 0x3f, 0x8c, 0x3d, 0x1b, 0x29, 0x3f, 0x87, 0x13, 0xff, 0x8e, 0xdf, 0x80,
	0xd6, 0x49, 0xd0, 0x6e, 0x88, 0x54, 0x6e, 0xe3, 0xe7, 0x99, 0x37, 0x33, 0xef, 0xd9, 0xf0, 0x5c,
	0xc7, 0x93, 0x54, 0xc5, 0x3a, 0x91, 0xfa, 0xda, 0x60, 0x56, 0x10, 0x8e, 0xb5, 0x29, 0xa8, 0xe0,
	0x5e, 0x0d, 0x0a, 0x1f, 0x41, 0xe7, 0x32, 0xd3, 0xb4, 0x09, 0x7f, 0xb6, 0x60, 0x78, 0xa5, 0x2c,
	0xcd, 0x73, 0x42, 0x73, 0x23, 0x13, 0xb4, 0x02, 0x75, 0xba, 0xe1, 0xdf, 0x60, 0xa0, 0xf6, 0x50,
	0x75, 0xef, 0xb3, 0xa0, 0x1d, 0x79, 0xd3, 0xd9, 0xb8, 0x4e, 0x7c, 0xa4, 0x70, 0x3c, 0xaf, 0x57,
	0x5d, 0xe6, 0x64, 0x36, 0xa2, 0xc9, 0x34, 0x4a, 0x81, 0xff, 0x9b, 0xc4, 0x9f, 0x40, 0xfb, 0x1e,
	0x37, 0x3e, 0x0b, 0x58, 0xd4, 0x13, 0x55, 0xc8, 0xdf, 0x43, 0x67, 0x2d, 0xd3, 0x12, 0xfd, 0x56,
	0xc0, 0x22, 0x6f, 0xfa, 0xea, 0xff, 0x5b, 0x8b, 0x6d, 0xe1, 0xbb, 0xd6, 0x5b, 0x36, 0xfa, 0x00,
	0xbd, 0xbf, 0x38, 0xe7, 0x70, 0x9a, 0xcb, 0x0c, 0x77, 0x5d, 0x5c, 0xcc, 0x03, 0xf0, 0x56, 0x68,
	0x13, 0xa3, 0x34, 0xa9, 0x22, 0x77, 0xcd, 0x7a, 0xa2, 0x0e, 0x85, 0xbf, 0x18, 0x0c, 0x97, 0x24,
	0x0d, 0x7d, 0x92, 0x9a, 0x4a, 0x83, 0x02, 0x7f, 0x94, 0x68, 0xa9, 0x62, 0x2b, 0x4b, 0xb5, 0xda,
	0xb3, 0x55, 0x31, 0x7f, 0x06, 0xdd, 0x15, 0xae, 0x55, 0x82, 0x3b, 0xa2, 0xdd, 0x89, 0xbf, 0x80,
	0xbe, 0xcd, 0xa5, 0xb6, 0x77, 0x05, 0x5d, 0xa7, 0x98, 0xfb, 0xed, 0x80, 0x45, 0x03, 0xe1, 0xed,
	0xb1, 0x2b, 0xcc, 0xab, 0x41, 0xb4, 0x29, 0x32, 0x65, 0x93, 0xb2, 0x28, 0xad, 0x7f, 0x1a, 0xb0,
	0xe8, 0xb1, 0xa8, 0x43, 0xfc, 0x1c, 0xb6, 0x26, 0xde, 0xa8, 0x94, 0xd0, 0xf8, 0x1d, 0xd7, 0x01,
	0x2a, 0xe8, 0xb3, 0x43, 0xc2, 0x08, 0xf8, 0x92, 0x0a, 0xfd, 0xf0, 0x9c, 0xe1, 0x05, 0x74, 0x17,
	0x32, 0xb9, 0x47, 0xe2, 0x67, 0xd0, 0x22, 0xeb, 0xee, 0xda, 0xa2, 0x45, 0xb6, 0xca, 0x5e, 0xa7,
	0x72, 0x2b, 0xc4, 0x40, 0xb8, 0xb8, 0xda, 0x4a, 0xbb, 0x6c, 0x37, 0x77, 0x5f, 0xec, 0x4e, 0xd3,
	0xdf, 0x0c, 0x9e, 0x2e, 0x12, 0xa9, 0x85, 0x33, 0x65, 0x89, 0xc6, 0xed, 0xfa, 0x05, 0xce, 0x9a,
	0xf6, 0x70, 0xde, 0xf0, 0xce, 0xbd, 0xbc, 0x51, 0xf0, 0x90, 0x9f, 0xe1, 0x09, 0x9f, 0x43, 0xbf,
	0x2e, 0x3c, 0x6f, 0xd6, 0x1c, 0xf1, 0x64, 0x34, 0x6c, 0x64, 0x6c, 0x57, 0x0c, 0x4f, 0xde, 0x30,
	0x7e, 0x01, 0x5e, 0x4d, 0x1a, 0x7e, 0x7e, 0xc0, 0x74, 0x28, 0xda, 0xe8, 0xc8, 0xc8, 0xe1, 0xc9,
	0xc7, 0xd7, 0xdf, 0x5f, 0xde, 0x2a, 0xba, 0x2b, 0xe3, 0x71, 0x52, 0x64, 0x93, 0xe5, 0x42, 0x7c,
	0xbd, 0xb5, 0x84, 0xe6, 0xe0, 0xc7, 0x4d, 0xd6, 0xb3, 0x89, 0x8e, 0xe3, 0xae, 0xfb, 0x78, 0xb3,
	0x3f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x6b, 0x0b, 0xa8, 0x77, 0x93, 0x03, 0x00, 0x00,
}
