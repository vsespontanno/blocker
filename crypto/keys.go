package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
)

const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedlen    = 32 // Length of the seed for ed25519 keys
	addressLen = 20
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

func NewPrivateKeyFromString(s string) *PrivateKey {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("Invalid private key string: " + err.Error())
	}
	return NewPrivateKeyFromSeed(b)
}

func NewPrivateKeyFromSeed(seed []byte) *PrivateKey {
	if len(seed) != seedlen {
		panic("Invalid seed length")
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

func GeneratePrivateKey() *PrivateKey {
	seed := make([]byte, seedlen)
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic("Failed to generate random seed for private key: " + err.Error())
	}
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{value: ed25519.Sign(p.key, msg)}
}

func (p *PrivateKey) Public() *PublicKey {
	b := make([]byte, pubKeyLen)
	copy(b, p.key[32:]) // Skip the first 32 bytes which are the seed
	return &PublicKey{key: b}
}

type PublicKey struct {
	key ed25519.PublicKey
}

func (p *PublicKey) Address() *Address {
	return &Address{
		value: p.key[len(p.key)-addressLen:],
	}
}

func (p *PublicKey) Bytes() []byte {
	return p.key
}

type Signature struct {
	value []byte
}

func (s *Signature) Bytes() []byte {
	return s.value
}

func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	return ed25519.Verify(pubKey.Bytes(), msg, s.value)
}

type Address struct {
	value []byte
}

func (a *Address) Bytes() []byte {
	return a.value
}

func (a *Address) String() string {
	return hex.EncodeToString(a.value)
}
