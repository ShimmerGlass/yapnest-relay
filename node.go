package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// A registration: where to push, and the only account allowed to ask for it.
type registration struct {
	Token   []byte // the APNs device token
	Sandbox bool   // a development build's token, for api.sandbox.push.apple.com
	Owner   string // the bare JID that registered it
}

// environment is the APNs environment the token belongs to, as a metrics label.
func (r registration) environment() string {
	if r.Sandbox {
		return "sandbox"
	}
	return "production"
}

// Nodes carry their registration, sealed with the relay's key, so the relay keeps no state and the user's
// server never sees the device token. Sealing is deterministic (the nonce derives from the contents): a device
// that registers again gets the same node, so its server replaces the push target instead of adding a second.
type sealer struct {
	aead     cipher.AEAD
	nonceKey []byte
}

const nodeVersion = 1

func newSealer(key []byte) (*sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("the relay key needs at least 32 bytes")
	}
	block, err := aes.NewCipher(subkey(key, "node encryption"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead, nonceKey: subkey(key, "node nonce")}, nil
}

func subkey(key []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

func (s *sealer) seal(r registration) (string, error) {
	if len(r.Token) == 0 || len(r.Token) > 255 {
		return "", errors.New("bad device token length")
	}
	env := byte(0)
	if r.Sandbox {
		env = 1
	}
	plain := append([]byte{nodeVersion, env, byte(len(r.Token))}, r.Token...)
	plain = append(plain, normalizeJID(r.Owner)...)

	mac := hmac.New(sha256.New, s.nonceKey)
	mac.Write(plain)
	nonce := mac.Sum(nil)[:s.aead.NonceSize()]
	sealed := s.aead.Seal(append([]byte{}, nonce...), nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

var errBadNode = errors.New("not a node of this relay")

func (s *sealer) open(node string) (registration, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(node)
	if err != nil || len(sealed) < s.aead.NonceSize() {
		return registration{}, errBadNode
	}
	nonce, box := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, box, nil)
	if err != nil || len(plain) < 3 || plain[0] != nodeVersion || len(plain) < 3+int(plain[2]) {
		return registration{}, errBadNode
	}
	n := int(plain[2])
	return registration{
		Token:   plain[3 : 3+n],
		Sandbox: plain[1] == 1,
		Owner:   string(plain[3+n:]),
	}, nil
}

// normalizeJID returns the bare JID, lowercased: enough to compare the JID that registered a node with the one
// that publishes to it, which both come from servers that already normalized them.
func normalizeJID(jid string) string {
	if i := strings.IndexByte(jid, '/'); i >= 0 {
		jid = jid[:i]
	}
	return strings.ToLower(jid)
}
