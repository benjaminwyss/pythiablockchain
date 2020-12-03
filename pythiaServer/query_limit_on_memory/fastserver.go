package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"github.com/valyala/fasthttp"
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

type QueryNote struct {
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

var contract *gateway.Contract
var gw *gateway.Gateway
var queryNotes map[string]QueryNote
var mutex = sync.RWMutex{}
var QUERY_LIMIT int = 10

func init() {
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

	gw, err = gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, "user"),
	)
	if err != nil {
		fmt.Printf("Failed to connect to gateway: %s\n", err)
		os.Exit(1)
	}

	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		fmt.Printf("Failed to get network: %s\n", err)
		os.Exit(1)
	}

	contract = network.GetContract("pythia")

	fmt.Printf("Blockchain connection initialized\n")

	queryNotes = make(map[string]QueryNote)

}

func queryHandler(ctx *fasthttp.RequestCtx) {
	args := ctx.PostArgs()

	x := string(args.Peek("x"))
	t := args.Peek("t")
	w := string(args.Peek("w"))
	proof := args.GetBool("p")

	salt := fmt.Sprintf("%b", t)

	//check query rate limiting

	now := time.Now()
	count := 1

	mutex.RLock()
	queryNote, ok := queryNotes[salt]
	mutex.RUnlock()
	if ok {
		expireTime := queryNote.Timestamp.Add(time.Hour)

		if now.Before(expireTime) {
			count += queryNote.Count
		}

		if count > QUERY_LIMIT {
			ctx.WriteString("Error\nQuery rate limit exceeded")
			return
		}
	}

	note := QueryNote{count, now}
	mutex.Lock()
	queryNotes[salt] = note
	mutex.Unlock()

	transientMap := make(map[string][]byte)
	wBytes, _ := hex.DecodeString(w)
	transientMap["identity"] = wBytes

	if proof {
		txn, err := contract.CreateTransaction("QueryWithProof", gateway.WithTransient(transientMap))
		resultBytes, err := txn.Evaluate(salt, x)

		if err != nil {
			ctx.WriteString("Error\nFailed to query pythia contract: " + err.Error() + "\n")
			return
		}

		var resultWithProof ResultWithProof

		if err := json.Unmarshal(resultBytes, &resultWithProof); err != nil {
			ctx.WriteString("Error\nFailed to convert result to type ResultWithProof: " + err.Error() + "\n")
			return
		}

		ctx.WriteString(resultWithProof.Result + "\n" + resultWithProof.P + "\n" + resultWithProof.C + "\n" + resultWithProof.U + "\n")

	} else {
		txn, err := contract.CreateTransaction("Query", gateway.WithTransient(transientMap))
		resultBytes, err := txn.Evaluate(salt, x)

		if err != nil {
			ctx.WriteString("Error\nFailed to query pythia contract: " + err.Error() + "\n")
			return
		}

		result := string(resultBytes)

		ctx.WriteString(result)
	}

}

func main() {
	defer gw.Close()

	requestHandler := func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/query":
			queryHandler(ctx)
		default:
			ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		}
	}

	fasthttp.ListenAndServe(":8080", nil)
}
