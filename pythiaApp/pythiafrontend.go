package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/benjaminwyss/pythia"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"golang.org/x/crypto/bn256"
)

type ResultWithProof struct {
	Result string `json:"result"`
	P      string `json:"p"`
	C      string `json:"c"`
	U      string `json:"u"`
}

type UpdateTokenPackage struct {
	UpdateToken string `json:"updateToken"`
	PPrime      string `json:"pPrime"`
}

func endToEndTest() {
	//end to end test is outdated as pythia contract function parameters have changed
	os.Setenv("DISCOVERY_AS_LOCALHOST", "false")

	wallet, err := gateway.NewFileSystemWallet("../wallet")

	if err != nil {
		fmt.Printf("Failed to create wallet: %s\n", err)
		os.Exit(1)
	}

	if !wallet.Exists("user") {
		fmt.Printf("Wallet user does not exist")
		os.Exit(1)
	}

	ccpPath := filepath.Join(
		"..",
		"crypto-config",
		"peerOrganizations",
		"org1.example.com",
		"connectionprofile.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "user"),
	)
	if err != nil {
		fmt.Printf("Failed to connect to gateway: %s\n", err)
		os.Exit(1)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		fmt.Printf("Failed to get network: %s\n", err)
		os.Exit(1)
	}

	contract := network.GetContract("pythia")

	//test msk initialization

	transientMap := make(map[string][]byte)

	msk, err := rand.Int(rand.Reader, bn256.Order)

	transientMap["msk"] = msk.Bytes()

	txn, err := contract.CreateTransaction("Init", gateway.WithTransient(transientMap))
	_, err = txn.Submit()

	if err != nil {
		fmt.Printf("Failed to submit initialization transaction: %s\n", err)
	}

	//test identity registration

	identity, _ := rand.Int(rand.Reader, bn256.Order)
	identityStr := hex.EncodeToString(identity.Bytes())

	prekey, _ := rand.Int(rand.Reader, bn256.Order)
	prekeyStr := hex.EncodeToString(prekey.Bytes())

	_, err = contract.SubmitTransaction("Register", identityStr, prekeyStr)

	if err != nil {
		fmt.Printf("Failed to register identity on pythia contract: %s\n", err)
		os.Exit(1)
	}

	//test determinism of queries

	blindHash1, rInv1 := pythia.HashBlind("password")
	blindHash2, rInv2 := pythia.HashBlind("password")

	blindHash1Str := hex.EncodeToString(blindHash1)
	blindHash2Str := hex.EncodeToString(blindHash2)

	result1Bytes, err := contract.EvaluateTransaction("Query", identityStr, "salt", blindHash1Str)

	if err != nil {
		fmt.Printf("Failed to query pythia contract (test 1): %s\n", err)
		os.Exit(1)
	}

	result2Bytes, err := contract.EvaluateTransaction("Query", identityStr, "salt", blindHash2Str)

	if err != nil {
		fmt.Printf("Failed to query pythia contract (test 2): %s\n", err)
		os.Exit(1)
	}

	result1 := string(result1Bytes)
	result2 := string(result2Bytes)

	gt1 := new(bn256.GT)
	gt2 := new(bn256.GT)

	result1Bytes, _ = hex.DecodeString(result1)
	result2Bytes, _ = hex.DecodeString(result2)

	gt1.Unmarshal(result1Bytes)
	gt2.Unmarshal(result2Bytes)

	result1Bytes = pythia.UnblindGT(gt1, rInv1)
	result2Bytes = pythia.UnblindGT(gt2, rInv2)

	result1 = hex.EncodeToString(result1Bytes)
	result2 = hex.EncodeToString(result2Bytes)

	if result1 == result2 {
		fmt.Printf("Test finished successfully! Two pythia contract queries with different blinding values match!\n")
	} else {
		fmt.Printf("Deterministic Test failed\nResult 1 = %s\nResult 2 = %s\n", result1, result2)
	}

}

func pythiaMenu() {
	os.Setenv("DISCOVERY_AS_LOCALHOST", "false")

	wallet, err := gateway.NewFileSystemWallet("../wallet")

	if err != nil {
		fmt.Printf("Failed to create wallet: %s\n", err)
		os.Exit(1)
	}

	if !wallet.Exists("user") {
		fmt.Printf("Wallet user does not exist")
		os.Exit(1)
	}

	ccpPath := filepath.Join(
		"..",
		"crypto-config",
		"peerOrganizations",
		"org1.example.com",
		"connectionprofile.yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "user"),
	)
	if err != nil {
		fmt.Printf("Failed to connect to gateway: %s\n", err)
		os.Exit(1)
	}
	defer gw.Close()

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		fmt.Printf("Failed to get network: %s\n", err)
		os.Exit(1)
	}

	contract := network.GetContract("pythia")

	for {
		fmt.Printf("Pythia Interactive CLI Menu:\n1) Initialize msk\n2) Register Identity\n3) Query\n4) Query With Proof\n5) Generate Update Token\n6) Apply Update Token\n7) Exit\n\nYour Choice? ")
		var choice string
		fmt.Scanln(&choice)

		fmt.Printf("\n")

		if choice == "1" {
			transientMap := make(map[string][]byte)

			msk, err := rand.Int(rand.Reader, bn256.Order)

			transientMap["msk"] = msk.Bytes()

			txn, err := contract.CreateTransaction("Init", gateway.WithTransient(transientMap))
			_, err = txn.Submit()

			if err != nil {
				fmt.Printf("Failed to submit initialization transaction: %s\n", err)
			} else {
				fmt.Printf("msk successfully initialized!\n\n")
			}
		} else if choice == "2" {
			identity, _ := rand.Int(rand.Reader, bn256.Order)
			identityStr := hex.EncodeToString(identity.Bytes())

			prekey, _ := rand.Int(rand.Reader, bn256.Order)

			transientMap := make(map[string][]byte)
			transientMap["identity"] = identity.Bytes()
			transientMap["prekey"] = prekey.Bytes()

			txn, err := contract.CreateTransaction("Register", gateway.WithTransient(transientMap))
			resultBytes, err := txn.Submit()

			result := string(resultBytes)

			if err != nil {
				fmt.Printf("Failed to register identity on pythia contract: %s\n", err)
			} else {
				fmt.Printf("Identity successfully registered!\nYour pythia public key is: %s\nYour identity is: %s\n\n", result, identityStr)
			}
		} else if choice == "3" {
			var password, salt, identity string

			fmt.Printf("Input Password: ")
			fmt.Scanln(&password)
			fmt.Printf("Input Salt: ")
			fmt.Scanln(&salt)
			fmt.Printf("Input Identity: ")
			fmt.Scanln(&identity)
			fmt.Printf("\n")

			blindHash, rInv := pythia.HashBlind(password)
			blindHashStr := hex.EncodeToString(blindHash)

			transientMap := make(map[string][]byte)
			identityBytes, _ := hex.DecodeString(identity)
			transientMap["identity"] = identityBytes

			txn, err := contract.CreateTransaction("Query", gateway.WithTransient(transientMap))
			resultBytes, err := txn.Evaluate(salt, blindHashStr)

			if err != nil {
				fmt.Printf("Failed to query pythia contract: %s\n", err)
				continue
			}

			result := string(resultBytes)

			gt := new(bn256.GT)

			resultBytes, _ = hex.DecodeString(result)

			gt.Unmarshal(resultBytes)

			resultBytes = pythia.UnblindGT(gt, rInv)

			result = hex.EncodeToString(resultBytes)

			fmt.Printf("Query Successful! Result:\n%s\n\n", result)

		} else if choice == "4" {
			var password, salt, identity string

			fmt.Printf("Input Password: ")
			fmt.Scanln(&password)
			fmt.Printf("Input Salt: ")
			fmt.Scanln(&salt)
			fmt.Printf("Input Identity: ")
			fmt.Scanln(&identity)
			fmt.Printf("\n")

			blindHash, rInv := pythia.HashBlind(password)
			blindHashStr := hex.EncodeToString(blindHash)

			transientMap := make(map[string][]byte)
			identityBytes, _ := hex.DecodeString(identity)
			transientMap["identity"] = identityBytes

			txn, err := contract.CreateTransaction("QueryWithProof", gateway.WithTransient(transientMap))
			resultBytes, err := txn.Evaluate(salt, blindHashStr)

			if err != nil {
				fmt.Printf("Failed to query pythia contract: %s\n", err)
				continue
			}

			var resultWithProof ResultWithProof

			if err := json.Unmarshal(resultBytes, &resultWithProof); err != nil {
				fmt.Printf("Failed to convert result to type ResultWithProof: %s", err)
			}

			p, _ := hex.DecodeString(resultWithProof.P)
			cBytes, _ := hex.DecodeString(resultWithProof.C)
			uBytes, _ := hex.DecodeString(resultWithProof.U)

			c := new(big.Int).SetBytes(cBytes)
			u := new(big.Int).SetBytes(uBytes)

			blindResult, _ := hex.DecodeString(resultWithProof.Result)

			if !pythia.VerifyProof(blindHash, salt, blindResult, p, c, u) {
				fmt.Printf("Proof failed to verify!")
			} else {
				gt := new(bn256.GT)
				gt.Unmarshal(blindResult)
				resultBytes := pythia.UnblindGT(gt, rInv)
				result := hex.EncodeToString(resultBytes)

				fmt.Printf("Query Successful and Proof Validated!\nPythia public key: %s\nResult:\n%s\n\n", resultWithProof.P, result)

			}

		} else if choice == "5" {
			var identity string
			fmt.Printf("Input Identity: ")
			fmt.Scanln(&identity)

			prekey, _ := rand.Int(rand.Reader, bn256.Order)
			identityBytes, _ := hex.DecodeString(identity)

			transientMap := make(map[string][]byte)
			transientMap["identity"] = identityBytes
			transientMap["prekey"] = prekey.Bytes()

			txn, err := contract.CreateTransaction("GenerateUpdateToken", gateway.WithTransient(transientMap))
			resultBytes, err := txn.Submit()

			if err != nil {
				fmt.Printf("Failed to query pythia contract: %s\n", err)
				continue
			}

			var updateTokenPackage UpdateTokenPackage

			if err := json.Unmarshal(resultBytes, &updateTokenPackage); err != nil {
				fmt.Printf("Failed to convert result to type UpdateTokenPackage: %s", err)
			} else {
				fmt.Printf("Update Token Successfully Generated and Pythia Secret Key Updated!\nNew Pythia Public Key: %s\nUpdate Token: %s\n\n", updateTokenPackage.PPrime, updateTokenPackage.UpdateToken)
			}

		} else if choice == "6" {
			var hash, token string
			fmt.Printf("Input Password Hash: ")
			fmt.Scanln(&hash)
			fmt.Printf("Input Update Token: ")
			fmt.Scanln(&token)

			hashBytes, _ := hex.DecodeString(hash)
			tokenBytes, _ := hex.DecodeString(token)

			tokenInt := new(big.Int).SetBytes(tokenBytes)

			updatedHashBytes := pythia.ApplyUpdateToken(hashBytes, tokenInt)
			updatedHash := hex.EncodeToString(updatedHashBytes)

			fmt.Printf("Update Token Successfully Applied!\nResult:\n%s\n\n", updatedHash)
		} else if choice == "7" {
			return
		} else {
			fmt.Printf("Choice not recognized\n\n")
		}
	}
}

func main() {
	pythiaMenu()
}
