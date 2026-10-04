package wire3

import (
	"encoding/base64"
	"strconv"
)

// Binary values in hub wire 3 (core CORE-E5).
//
// Every binary value a wire-3 request or response carries in JSON (a key
// history, a key set, a capability id, a proof-of-work seed, a directory
// prefix) is base64url without padding (RFC 4648 §5). The hub decodes them
// all with DecodeB64URL, so that each value has exactly one spelling here:
//
//   - only the 64 characters A-Z, a-z, 0-9, "-" and "_". "=", "+", "/",
//     white space and anything else are refused. The standard decoder skips
//     "\r" and "\n" even in strict mode, so they are refused before it runs;
//   - no length that no encoding has (one character past a multiple of four);
//   - the unused low bits of the last character are zero. Otherwise "AB" and
//     "AA" would both decode to the one byte 0x00, and a value compared or
//     stored as text (a signature input, a log line) could differ from the
//     value decoded.
//
// A value that breaks a rule is refused as a *DecodeError (400 bad_request,
// RefuseDecode), like any other malformed request member.

// b64url is the decoder: base64url, no padding, trailing bits zero.
var b64url = base64.RawURLEncoding.Strict()

// DecodeB64URL decodes s, the value of the request member named member (a
// path into the body, such as "cap_ids[3]"; it names the value in the
// refusal). The empty string is the encoding of no bytes.
func DecodeB64URL(member, s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !b64urlChar(s[i]) {
			return nil, &DecodeError{Kind: KindB64URL, Member: member,
				Detail: "byte " + strconv.Itoa(i) + " is not in the base64url alphabet"}
		}
	}
	out, err := b64url.DecodeString(s)
	if err != nil {
		// Only a length of 4n+1 or non-zero trailing bits get here.
		return nil, &DecodeError{Kind: KindB64URL, Member: member, Detail: err.Error()}
	}
	return out, nil
}

// DecodeB64URLSize is DecodeB64URL for a value of exactly n bytes (a
// capability id is 16, a proof-of-work seed 32). A value of another length
// is a *DecodeError of KindSize.
func DecodeB64URLSize(member, s string, n int) ([]byte, error) {
	out, err := DecodeB64URL(member, s)
	if err != nil {
		return nil, err
	}
	if len(out) != n {
		return nil, &DecodeError{Kind: KindSize, Member: member, Size: n,
			Detail: strconv.Itoa(len(out)) + " bytes"}
	}
	return out, nil
}

// EncodeB64URL is the one spelling of b that DecodeB64URL accepts.
func EncodeB64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64urlChar reports whether c is one of the 64 characters of base64url.
func b64urlChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
