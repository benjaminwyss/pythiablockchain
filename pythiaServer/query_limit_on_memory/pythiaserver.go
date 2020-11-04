package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
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

func query(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	x := req.Form.Get("x")
	t := req.Form.Get("t")
	w := req.Form.Get("w")
	p := req.Form.Get("p")

	proof := false
	if p == "1" {
		proof = true
	}

	//convert salt to binary to prevent parameter switching avoiding rate limiting
	saltBytes := []byte(t)
	t = fmt.Sprintf("%b", saltBytes)

	//check query rate limiting

	now := time.Now()
	count := 1

	mutex.RLock()
	queryNote, ok := queryNotes[t]
	mutex.RUnlock()
	if ok {
		expireTime := queryNote.Timestamp.Add(time.Hour)

		if now.Before(expireTime) {
			count += queryNote.Count
		}

		if count > QUERY_LIMIT {
			fmt.Fprintf(res, "Error\nQuery rate limit exceeded")
			return
		}
	}

	note := QueryNote{count, now}
	mutex.Lock()
	queryNotes[t] = note
	mutex.Unlock()

	transientMap := make(map[string][]byte)
	wBytes, _ := hex.DecodeString(w)
	transientMap["identity"] = wBytes

	if proof {
		txn, err := contract.CreateTransaction("QueryWithProof", gateway.WithTransient(transientMap))
		resultBytes, err := txn.Evaluate(t, x)

		if err != nil {
			fmt.Fprintf(res, "Error\nFailed to query pythia contract: %s\n", err)
			return
		}

		var resultWithProof ResultWithProof

		if err := json.Unmarshal(resultBytes, &resultWithProof); err != nil {
			fmt.Fprintf(res, "Error\nFailed to convert result to type ResultWithProof: %s", err)
			return
		}

		fmt.Fprintf(res, "%s\n%s\n%s\n%s", resultWithProof.Result, resultWithProof.P, resultWithProof.C, resultWithProof.U)

	} else {
		txn, err := contract.CreateTransaction("Query", gateway.WithTransient(transientMap))
		resultBytes, err := txn.Evaluate(t, x)

		if err != nil {
			fmt.Fprintf(res, "Error\nFailed to query pythia contract: %s\n", err)
			return
		}

		result := string(resultBytes)

		fmt.Fprintf(res, "%s", result)
	}

}

func register(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	wStr := req.Form.Get("w")
	prekeyStr := req.Form.Get("prekey")

	w, _ := hex.DecodeString(wStr)
	prekey, _ := hex.DecodeString(prekeyStr)

	transientMap := make(map[string][]byte)
	transientMap["identity"] = w
	transientMap["prekey"] = prekey

	txn, err := contract.CreateTransaction("Register", gateway.WithTransient(transientMap))
	resultBytes, err := txn.Submit()

	if err != nil {
		fmt.Fprintf(res, "Error\nFailed to register on pythia contract: %s\n", err)
		return
	}

	result := string(resultBytes)

	fmt.Fprintf(res, "%s", result)

}

func registerEmail(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	wStr := req.Form.Get("w")
	emailStr := req.Form.Get("email")

	w, _ := hex.DecodeString(wStr)
	email := []byte(emailStr)

	transientMap := make(map[string][]byte)
	transientMap["identity"] = w
	transientMap["email"] = email

	txn, err := contract.CreateTransaction("RegisterEmail", gateway.WithTransient(transientMap))
	_, err = txn.Submit()

	if err != nil {
		fmt.Fprintf(res, "Error\nFailed to register email on pythia contract: %s\n", err)
		return
	}

	fmt.Fprintf(res, "success")

}

func genAuth(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	wStr := req.Form.Get("w")

	w, _ := hex.DecodeString(wStr)

	transientMap := make(map[string][]byte)
	transientMap["identity"] = w

	txn, err := contract.CreateTransaction("GenerateAuthToken", gateway.WithTransient(transientMap))
	resultBytes, err := txn.Evaluate()

	if err != nil {
		fmt.Fprintf(res, "Error\nFailed to generate authorization token.\n%s\n", err)
		return
	}

	result := string(resultBytes)

	fmt.Fprintf(res, "%s", result)

}

func genUpdate(res http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	wStr := req.Form.Get("w")
	prekeyStr := req.Form.Get("prekey")
	authTokenStr := req.Form.Get("authToken")

	w, _ := hex.DecodeString(wStr)
	prekey, _ := hex.DecodeString(prekeyStr)
	authToken, _ := hex.DecodeString(authTokenStr)

	transientMap := make(map[string][]byte)
	transientMap["identity"] = w
	transientMap["prekey"] = prekey
	transientMap["authToken"] = authToken

	txn, err := contract.CreateTransaction("GenerateUpdateToken", gateway.WithTransient(transientMap))
	resultBytes, err := txn.Submit()

	if err != nil {
		fmt.Fprintf(res, "Error\nFailed to query pythia contract: %s\n", err)
		return
	}

	var updateTokenPackage UpdateTokenPackage

	if err := json.Unmarshal(resultBytes, &updateTokenPackage); err != nil {
		fmt.Fprintf(res, "Error\nFailed to convert result to type UpdateTokenPackage: %s", err)
		return
	}

	fmt.Fprintf(res, "%s\n%s", updateTokenPackage.UpdateToken, updateTokenPackage.PPrime)
}

func main() {

	defer gw.Close()

	http.HandleFunc("/query", query)
	http.HandleFunc("/register", register)
	http.HandleFunc("/genUpdate", genUpdate)
	http.HandleFunc("/registerEmail", registerEmail)
	http.HandleFunc("/genAuth", genAuth)

	http.ListenAndServe(":8080", nil)
}
