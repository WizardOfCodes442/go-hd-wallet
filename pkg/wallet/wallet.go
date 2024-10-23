package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"
)

// ErrInvalidWordCount indicates an unsupported number of mnemonic words.
var ErrInvalidWordCount = fmt.Errorf("invalid word count: must be 12, 15, 18, 21, or 24")

// GenerateMnemonic generates a new BIP-39 mnemonic with the specified number of words.
func GenerateMnemonic(numWords int) (string, error) {
	validCounts := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
	if !validCounts[numWords] {
		return "", ErrInvalidWordCount
	}

	entropySize := (numWords * 11) / 8
	entropy := make([]byte, entropySize)

	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}

// GenerateMasterKey creates a master key from a mnemonic and optional passphrase.
func GenerateMasterKey(mnemonic, passphrase string) (*hdkeychain.ExtendedKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	return masterKey, nil
}

// GetPrivateKey extracts the private key bytes from an HD key and returns it as a hex string.
func GetPrivateKey(key *hdkeychain.ExtendedKey) (string, error) {
	privKey, err := key.ECPrivKey()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}

	// Use Decred's secp256k1/v4 to handle the private key.
	rawKey := privKey.Serialize() // Get the raw private key bytes.
	return hex.EncodeToString(rawKey), nil
}

// GenerateNewKeyPair creates a new ECDSA key pair using secp256k1/v4.
func GenerateNewKeyPair() (*secp256k1.PrivateKey, *secp256k1.PublicKey, error) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privKey, privKey.PubKey(), nil
}

// ZeroBytes securely zeroes out a byte slice to avoid leaving sensitive data in memory.
func ZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
