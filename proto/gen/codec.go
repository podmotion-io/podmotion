// Package agentpb contains hand-written gRPC stubs for M4.
// These replace protoc-generated code until CI has protoc available.
// The JSON codec is used so messages don't need to implement proto.Message.
// In M5, replace with real protoc output and remove this file.
package agentpb

import (
	"encoding/json"
	"fmt"

	"google.golang.org/grpc/encoding"
)

func init() {
	encoding.RegisterCodec(JSONCodec{})
}

// JSONCodec is a gRPC codec that uses encoding/json instead of protobuf wire format.
// This avoids the need for proto.Message implementations on hand-written structs.
type JSONCodec struct{}

func (JSONCodec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (JSONCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (JSONCodec) Name() string { return "proto" }

// Ensure JSONCodec satisfies the interface at compile time.
var _ encoding.Codec = JSONCodec{}

// ensure fmt is used (for potential future error formatting)
var _ = fmt.Sprintf
