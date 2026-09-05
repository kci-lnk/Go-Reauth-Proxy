package deepmonitor

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// proto.Clone owns mutable messages and byte slices, but immutable strings may
// still point into a much larger request allocation. Detach strings throughout
// the copied tree before charging and retaining metadata in the writer queue.
func cloneOwnedProto(message proto.Message) proto.Message {
	owned := proto.Clone(message)
	detachProtoStrings(owned.ProtoReflect())
	return owned
}

func detachProtoStrings(message protoreflect.Message) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsMap():
			source := value.Map()
			target := message.NewField(field).Map()
			source.Range(func(key protoreflect.MapKey, entry protoreflect.Value) bool {
				if field.MapKey().Kind() == protoreflect.StringKind {
					key = protoreflect.ValueOfString(strings.Clone(key.String())).MapKey()
				}
				target.Set(key, detachProtoValue(field.MapValue().Kind(), entry))
				return true
			})
			message.Set(field, protoreflect.ValueOfMap(target))
		case field.IsList():
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				list.Set(i, detachProtoValue(field.Kind(), list.Get(i)))
			}
		default:
			message.Set(field, detachProtoValue(field.Kind(), value))
		}
		return true
	})
}

func detachProtoValue(kind protoreflect.Kind, value protoreflect.Value) protoreflect.Value {
	switch kind {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(strings.Clone(value.String()))
	case protoreflect.MessageKind, protoreflect.GroupKind:
		detachProtoStrings(value.Message())
	}
	return value
}
