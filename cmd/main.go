package cmd

import (
	"fmt"
	"github.com/WizardOfCodes442/go-hd-wallet/pkg/wallet"
)

func main() {
	mnemonic, _ := wallet.GenerateMnemonic(12) // BIP-39 mnemonic
	fmt.Println("Generated Mnemonic:", mnemonic)

	masterKey, _ := wallet.GenerateMasterKey(mnemonic, "")
	fmt.Println("Master Key:", masterKey)
}
