package main

import (
	"fmt"
	"github.com/WizardOfCodes442/go-hd-wallet/pkg/wallet"
)

func main() {
	mnemonic, _ := wallet.GenerateMnemonic(12) // BIP-39 mnemonic
	fmt.Println("Generated Mnemonic:", mnemonic)

	masterKey, _ := wallet.GenerateMasterKey(mnemonic, "")
	fmt.Println("Master Key:", masterKey)

	publicKey := wallet.GetPublicKey(masterKey)
	fmt.Println("Public Key : ", publicKey)

	privateKey, _ := wallet.GetPrivateKey(masterKey)
	fmt.Println("Private Key:", privateKey)
}
