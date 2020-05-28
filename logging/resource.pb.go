// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0
// 	protoc        v3.12.1
// source: resource.proto

package logging

import (
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType        string          `protobuf:"bytes,1,opt,name=resourceType,proto3" json:"resourceType,omitempty"`
	Id                  string          `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	ApplicationName     string          `protobuf:"bytes,3,opt,name=applicationName,proto3" json:"applicationName,omitempty"`
	Category            string          `protobuf:"bytes,4,opt,name=category,proto3" json:"category,omitempty"`
	Component           string          `protobuf:"bytes,5,opt,name=component,proto3" json:"component,omitempty"`
	TransactionId       string          `protobuf:"bytes,6,opt,name=transactionId,proto3" json:"transactionId,omitempty"`
	ServiceName         string          `protobuf:"bytes,7,opt,name=serviceName,proto3" json:"serviceName,omitempty"`
	ApplicationInstance string          `protobuf:"bytes,8,opt,name=applicationInstance,proto3" json:"applicationInstance,omitempty"`
	ApplicationVersion  string          `protobuf:"bytes,9,opt,name=applicationVersion,proto3" json:"applicationVersion,omitempty"`
	OriginatingUser     string          `protobuf:"bytes,10,opt,name=originatingUser,proto3" json:"originatingUser,omitempty"`
	ServerName          string          `protobuf:"bytes,11,opt,name=serverName,proto3" json:"serverName,omitempty"`
	LogTime             string          `protobuf:"bytes,12,opt,name=logTime,proto3" json:"logTime,omitempty"`
	Severity            string          `protobuf:"bytes,13,opt,name=severity,proto3" json:"severity,omitempty"`
	EventId             string          `protobuf:"bytes,14,opt,name=eventId,proto3" json:"eventId,omitempty"`
	LogData             *LogData        `protobuf:"bytes,15,opt,name=logData,proto3" json:"logData,omitempty"`
	Custom              *_struct.Struct `protobuf:"bytes,16,opt,name=custom,proto3" json:"custom,omitempty"`
}

func (x *Resource) Reset() {
	*x = Resource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_resource_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource) ProtoMessage() {}

func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_resource_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource.ProtoReflect.Descriptor instead.
func (*Resource) Descriptor() ([]byte, []int) {
	return file_resource_proto_rawDescGZIP(), []int{0}
}

func (x *Resource) GetResourceType() string {
	if x != nil {
		return x.ResourceType
	}
	return ""
}

func (x *Resource) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Resource) GetApplicationName() string {
	if x != nil {
		return x.ApplicationName
	}
	return ""
}

func (x *Resource) GetCategory() string {
	if x != nil {
		return x.Category
	}
	return ""
}

func (x *Resource) GetComponent() string {
	if x != nil {
		return x.Component
	}
	return ""
}

func (x *Resource) GetTransactionId() string {
	if x != nil {
		return x.TransactionId
	}
	return ""
}

func (x *Resource) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

func (x *Resource) GetApplicationInstance() string {
	if x != nil {
		return x.ApplicationInstance
	}
	return ""
}

func (x *Resource) GetApplicationVersion() string {
	if x != nil {
		return x.ApplicationVersion
	}
	return ""
}

func (x *Resource) GetOriginatingUser() string {
	if x != nil {
		return x.OriginatingUser
	}
	return ""
}

func (x *Resource) GetServerName() string {
	if x != nil {
		return x.ServerName
	}
	return ""
}

func (x *Resource) GetLogTime() string {
	if x != nil {
		return x.LogTime
	}
	return ""
}

func (x *Resource) GetSeverity() string {
	if x != nil {
		return x.Severity
	}
	return ""
}

func (x *Resource) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *Resource) GetLogData() *LogData {
	if x != nil {
		return x.LogData
	}
	return nil
}

func (x *Resource) GetCustom() *_struct.Struct {
	if x != nil {
		return x.Custom
	}
	return nil
}

type LogData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *LogData) Reset() {
	*x = LogData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_resource_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogData) ProtoMessage() {}

func (x *LogData) ProtoReflect() protoreflect.Message {
	mi := &file_resource_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogData.ProtoReflect.Descriptor instead.
func (*LogData) Descriptor() ([]byte, []int) {
	return file_resource_proto_rawDescGZIP(), []int{1}
}

func (x *LogData) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type Bundle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType string     `protobuf:"bytes,1,opt,name=resourceType,proto3" json:"resourceType,omitempty"`
	Type         string     `protobuf:"bytes,2,opt,name=type,proto3" json:"type,omitempty"`
	Total        int64      `protobuf:"varint,3,opt,name=total,proto3" json:"total,omitempty"`
	ProductKey   string     `protobuf:"bytes,4,opt,name=productKey,proto3" json:"productKey,omitempty"`
	Entry        []*Element `protobuf:"bytes,5,rep,name=entry,proto3" json:"entry,omitempty"`
}

func (x *Bundle) Reset() {
	*x = Bundle{}
	if protoimpl.UnsafeEnabled {
		mi := &file_resource_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Bundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bundle) ProtoMessage() {}

func (x *Bundle) ProtoReflect() protoreflect.Message {
	mi := &file_resource_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bundle.ProtoReflect.Descriptor instead.
func (*Bundle) Descriptor() ([]byte, []int) {
	return file_resource_proto_rawDescGZIP(), []int{2}
}

func (x *Bundle) GetResourceType() string {
	if x != nil {
		return x.ResourceType
	}
	return ""
}

func (x *Bundle) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Bundle) GetTotal() int64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *Bundle) GetProductKey() string {
	if x != nil {
		return x.ProductKey
	}
	return ""
}

func (x *Bundle) GetEntry() []*Element {
	if x != nil {
		return x.Entry
	}
	return nil
}

type Element struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Resource *Resource `protobuf:"bytes,1,opt,name=resource,proto3" json:"resource,omitempty"`
}

func (x *Element) Reset() {
	*x = Element{}
	if protoimpl.UnsafeEnabled {
		mi := &file_resource_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Element) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Element) ProtoMessage() {}

func (x *Element) ProtoReflect() protoreflect.Message {
	mi := &file_resource_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Element.ProtoReflect.Descriptor instead.
func (*Element) Descriptor() ([]byte, []int) {
	return file_resource_proto_rawDescGZIP(), []int{3}
}

func (x *Element) GetResource() *Resource {
	if x != nil {
		return x.Resource
	}
	return nil
}

var File_resource_proto protoreflect.FileDescriptor

var file_resource_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75,
	0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc4, 0x04, 0x0a, 0x08, 0x52, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x28, 0x0a, 0x0f, 0x61, 0x70, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0f, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x79, 0x12,
	0x1c, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x12, 0x24, 0x0a,
	0x0d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61,
	0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x30, 0x0a, 0x13, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x13, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49,
	0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x61, 0x70, 0x70, 0x6c, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x12, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x28, 0x0a, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69,
	0x6e, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x55, 0x73, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x55, 0x73, 0x65,
	0x72, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x6c, 0x6f, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x0c, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x6c, 0x6f, 0x67, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x73,
	0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73,
	0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x49, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49,
	0x64, 0x12, 0x2b, 0x0a, 0x07, 0x6c, 0x6f, 0x67, 0x44, 0x61, 0x74, 0x61, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x11, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x4c, 0x6f,
	0x67, 0x44, 0x61, 0x74, 0x61, 0x52, 0x07, 0x6c, 0x6f, 0x67, 0x44, 0x61, 0x74, 0x61, 0x12, 0x2f,
	0x0a, 0x06, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x18, 0x10, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x06, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x22,
	0x23, 0x0a, 0x07, 0x4c, 0x6f, 0x67, 0x44, 0x61, 0x74, 0x61, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x22, 0x9f, 0x01, 0x0a, 0x06, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x12,
	0x22, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x1e, 0x0a,
	0x0a, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x4b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x4b, 0x65, 0x79, 0x12, 0x27, 0x0a,
	0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52,
	0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x22, 0x39, 0x0a, 0x07, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
	0x74, 0x12, 0x2e, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x52,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x42, 0x31, 0x5a, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x70, 0x68, 0x69, 0x6c, 0x69, 0x70, 0x73, 0x2d, 0x73, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65,
	0x2f, 0x67, 0x6f, 0x2d, 0x68, 0x73, 0x64, 0x70, 0x2d, 0x61, 0x70, 0x69, 0x2f, 0x6c, 0x6f, 0x67,
	0x67, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_resource_proto_rawDescOnce sync.Once
	file_resource_proto_rawDescData = file_resource_proto_rawDesc
)

func file_resource_proto_rawDescGZIP() []byte {
	file_resource_proto_rawDescOnce.Do(func() {
		file_resource_proto_rawDescData = protoimpl.X.CompressGZIP(file_resource_proto_rawDescData)
	})
	return file_resource_proto_rawDescData
}

var file_resource_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_resource_proto_goTypes = []interface{}{
	(*Resource)(nil),       // 0: resource.Resource
	(*LogData)(nil),        // 1: resource.LogData
	(*Bundle)(nil),         // 2: resource.Bundle
	(*Element)(nil),        // 3: resource.Element
	(*_struct.Struct)(nil), // 4: google.protobuf.Struct
}
var file_resource_proto_depIdxs = []int32{
	1, // 0: resource.Resource.logData:type_name -> resource.LogData
	4, // 1: resource.Resource.custom:type_name -> google.protobuf.Struct
	3, // 2: resource.Bundle.entry:type_name -> resource.Element
	0, // 3: resource.Element.resource:type_name -> resource.Resource
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_resource_proto_init() }
func file_resource_proto_init() {
	if File_resource_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_resource_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_resource_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_resource_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Bundle); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_resource_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Element); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_resource_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_resource_proto_goTypes,
		DependencyIndexes: file_resource_proto_depIdxs,
		MessageInfos:      file_resource_proto_msgTypes,
	}.Build()
	File_resource_proto = out.File
	file_resource_proto_rawDesc = nil
	file_resource_proto_goTypes = nil
	file_resource_proto_depIdxs = nil
}
