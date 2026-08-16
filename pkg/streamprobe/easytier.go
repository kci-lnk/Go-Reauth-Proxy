package streamprobe

import (
	"encoding/binary"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	easyTierMagic             = uint64(0xd1e1a5e1)
	easyTierProtocolVersion   = uint64(1)
	easyTierTCPMaxBodySize    = 2000
	easyTierPeerHeaderSize    = 16
	easyTierHandshakeType     = byte(2)
	easyTierProbePeerID       = uint32(0x464e4b50) // "FNKP"
	easyTierProbeNetworkName  = "fn-knock-probe"
	easyTierSecretDigestBytes = 32
)

func easyTierProbePayload() []byte {
	handshake := make([]byte, 0, 64)
	handshake = protowire.AppendTag(handshake, 1, protowire.VarintType)
	handshake = protowire.AppendVarint(handshake, easyTierMagic)
	handshake = protowire.AppendTag(handshake, 2, protowire.VarintType)
	handshake = protowire.AppendVarint(handshake, uint64(easyTierProbePeerID))
	handshake = protowire.AppendTag(handshake, 3, protowire.VarintType)
	handshake = protowire.AppendVarint(handshake, easyTierProtocolVersion)
	handshake = protowire.AppendTag(handshake, 5, protowire.BytesType)
	handshake = protowire.AppendString(handshake, easyTierProbeNetworkName)
	handshake = protowire.AppendTag(handshake, 6, protowire.BytesType)
	handshake = protowire.AppendBytes(handshake, make([]byte, easyTierSecretDigestBytes))

	bodyLength := easyTierPeerHeaderSize + len(handshake)
	frame := make([]byte, 4+bodyLength)
	binary.LittleEndian.PutUint32(frame[:4], uint32(bodyLength))
	binary.LittleEndian.PutUint32(frame[4:8], easyTierProbePeerID)
	frame[12] = easyTierHandshakeType
	frame[14] = 1 // PeerManagerHeader.forward_counter
	binary.LittleEndian.PutUint32(frame[16:20], uint32(len(handshake)))
	copy(frame[20:], handshake)
	return frame
}

func classifyEasyTierHandshake(data []byte) Classification {
	const serviceID = "easytier"
	if len(data) < 4 {
		return Classification{ServiceID: serviceID, State: ValidationNeedMore}
	}
	bodyLength := int(binary.LittleEndian.Uint32(data[:4]))
	if bodyLength < easyTierPeerHeaderSize || bodyLength > easyTierTCPMaxBodySize {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	if len(data) < 4+bodyLength {
		return Classification{ServiceID: serviceID, State: ValidationNeedMore}
	}
	body := data[4 : 4+bodyLength]
	payloadLength := int(binary.LittleEndian.Uint32(body[12:16]))
	if payloadLength != bodyLength-easyTierPeerHeaderSize || body[8] != easyTierHandshakeType {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	// EasyTier v2.6.4 starts a traditional TCP peer handshake with an
	// unencrypted protobuf carrying this service-specific magic value. The
	// remaining structural checks prevent a coincidental magic byte sequence
	// from identifying an unrelated length-framed protocol as EasyTier.
	if !validEasyTierHandshakeProtobuf(body[easyTierPeerHeaderSize:]) {
		return Classification{ServiceID: serviceID, State: ValidationMismatch}
	}
	return Classification{
		ServiceID: serviceID,
		State:     ValidationMatch,
		Evidence:  "easytier_handshake_magic",
	}
}

func validEasyTierHandshakeProtobuf(data []byte) bool {
	var magicOK, peerIDPresent, versionOK, networkNameOK, digestOK bool
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 {
			return false
		}
		data = data[tagLength:]
		switch number {
		case 1, 2, 3:
			if wireType != protowire.VarintType {
				return false
			}
			value, valueLength := protowire.ConsumeVarint(data)
			if valueLength < 0 {
				return false
			}
			data = data[valueLength:]
			switch number {
			case 1:
				magicOK = value == easyTierMagic
			case 2:
				peerIDPresent = true
			case 3:
				versionOK = value == easyTierProtocolVersion
			}
		case 5, 6:
			if wireType != protowire.BytesType {
				return false
			}
			value, valueLength := protowire.ConsumeBytes(data)
			if valueLength < 0 {
				return false
			}
			data = data[valueLength:]
			if number == 5 {
				networkNameOK = len(value) > 0 && len(value) <= 255 && utf8.Valid(value)
			} else {
				digestOK = len(value) == easyTierSecretDigestBytes
			}
		default:
			valueLength := protowire.ConsumeFieldValue(number, wireType, data)
			if valueLength < 0 {
				return false
			}
			data = data[valueLength:]
		}
	}
	return magicOK && peerIDPresent && versionOK && networkNameOK && digestOK
}
