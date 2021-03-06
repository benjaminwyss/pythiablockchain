package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/benjaminwyss/pythia"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

func testThroughput(organization string, peer string) {
	os.Setenv("DISCOVERY_AS_LOCALHOST", "false")

	wallet, err := gateway.NewFileSystemWallet("wallet")

	if err != nil {
		fmt.Printf("Failed to create wallet: %s\n", err)
		os.Exit(1)
	}

	if !wallet.Exists("admin" + organization) {
		fmt.Printf("Wallet user does not exist")
		os.Exit(1)
	}

	ccpPath := filepath.Join(
		"connectionprofile" + organization + "-" + peer + ".yaml",
	)

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "admin"+organization),
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

	contract := network.GetContract("parcae")

	identityBytes, _ := hex.DecodeString("64ec2c9b2648969e3883e1e8f8bbcc73ed170dac9a131e2e4c39da4a0ad1ab16")
	transientMap := make(map[string][]byte)
	transientMap["identity"] = identityBytes

	blindHash, _ := pythia.HashBlind("password")
	blindHashStr := hex.EncodeToString(blindHash)

	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < 1000; i++ {
		go func() {
			wg.Add(1)
			txn, err := contract.CreateTransaction("Query", gateway.WithTransient(transientMap))
			_, err = txn.Evaluate("salt", blindHashStr)

			if err != nil {
				fmt.Printf("Failed to query pythia contract: %s\n", err)
			}

			wg.Done()
		}()
	}

	wg.Wait()

	end := time.Since(start)

	fmt.Printf("Average Latency: %dms\nThroughput: %dq/s\n", end.Milliseconds()/1000, 1000000/end.Milliseconds())

}

func main() {
	testThroughput(os.Args[1], os.Args[2])
}
