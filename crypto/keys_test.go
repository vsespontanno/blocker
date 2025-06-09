package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed       = "8d611f29eca1cbbe584cc42ef9aac593cf29905e0de848e6b181fbe0a613f977"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "455933787e2575c8c45a150c6e3fee262eef17ec"
	)
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	// Test with invalid message
	assert.False(t, sig.Verify(pubKey, []byte("different message")))
	// Test with invalid public key
	invalidPrivKey := GeneratePrivateKey()
	InvalidPrivKeyPublic := invalidPrivKey.Public()
	assert.False(t, sig.Verify(InvalidPrivKeyPublic, msg))

}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()
	assert.Equal(t, addressLen, len(address.Bytes()))
}
