package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vsespontanno/blocker/crypto"
	"github.com/vsespontanno/blocker/util"
)

func TestHashBlock(t *testing.T) {
	block := util.RandomBlock()
	hash := HashBlock(block)
	assert.Equal(t, len(hash), 32)
}

func TestSignBlock(t *testing.T) {
	var (
		block   = util.RandomBlock()
		privkey = crypto.GeneratePrivateKey()
		pubkey  = privkey.Public()
	)
	sig := SignBlock(privkey, block)
	assert.Equal(t, 64, len(sig.Bytes()))
	assert.True(t, sig.Verify(pubkey, HashBlock(block)))
}
