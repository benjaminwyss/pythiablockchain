package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/benjaminwyss/pythia"
	"golang.org/x/crypto/bn256"
)

var static_urls = [5]string{"http://tulip.ittc.ku.edu:8080", "http://fennel.ittc.ku.edu:8080", "http://digdug.ittc.ku.edu:8080", "http://outlander.ittc.ku.edu:8080", "http://pinbot.ittc.ku.edu:8080"}
var identity string = "0efdd0691ac604d3f18a5d1dafc70197d3ccbef05204f5efdf29e889c13d4a5f"
var pubkey string = "4a0a0fd00c85ea080a5b75189266c3d85870acadd8a818c7cf4eb918770844f37ed2092d83377399954a7a50579d69cdb226a66e9f809a8e2911638f6fa19ac2"

func query(salt string, pass string, proof bool) bool {
	blindHash, rInv := pythia.HashBlind(pass)
	x := hex.EncodeToString(blindHash)

	p := "0"
	if proof {
		p = "1"
	}

	formData := url.Values{
		"w": {identity},
		"x": {x},
		"t": {salt},
		"p": {p},
	}

	res, _ := http.PostForm(static_urls[1]+"/query", formData)
	text, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	strs := strings.Split(string(text), "\n")

	if strs[0] == "Error" {
		fmt.Printf("%s", text)
		return false
	}

	if proof {
		if strs[1] != pubkey {
			fmt.Printf("Error\nPublic key provided by proof does not match stored pythia public key\n")
			return false
		}

		blindResult, _ := hex.DecodeString(strs[0])

		p, _ := hex.DecodeString(strs[1])
		cBytes, _ := hex.DecodeString(strs[2])
		uBytes, _ := hex.DecodeString(strs[3])

		c := new(big.Int).SetBytes(cBytes)
		u := new(big.Int).SetBytes(uBytes)

		saltBytes := []byte(salt)
		salt = fmt.Sprintf("%b", saltBytes)

		if !pythia.VerifyProof(blindHash, salt, blindResult, p, c, u) {
			fmt.Printf("Error\nProof failed to verify")
			return false
		} else {
			gt := new(bn256.GT)
			gt.Unmarshal(blindResult)
			resultBytes := pythia.UnblindGT(gt, rInv)
			hex.EncodeToString(resultBytes)

			return true
		}

	} else {
		resultBytes, _ := hex.DecodeString(strs[0])
		gt := new(bn256.GT)
		gt.Unmarshal(resultBytes)

		resultBytes = pythia.UnblindGT(gt, rInv)
		hex.EncodeToString(resultBytes)

		return true
	}

}

func timeQueries(queries int, warmups int, proof bool) {
	for i := 0; i < warmups; i++ {
		query(fmt.Sprintf("%d", i), "pass", proof)
	}

	start := time.Now()

	for i := 0; i < queries; i++ {
		query(fmt.Sprintf("%d", i), "pass", proof)
	}

	end := time.Since(start)

	var queriesI64 int64 = int64(queries)

	fmt.Printf("Total time to perform %d queries: %dms\nAverage time per query: %dms", queries, end.Milliseconds(), end.Milliseconds()/queriesI64)
}

func sendRegistrations(registrations int) {
	for i := 0; i < registrations; i++ {
		identityInt, _ := rand.Int(rand.Reader, bn256.Order)
		prekeyInt, _ := rand.Int(rand.Reader, bn256.Order)

		identityStr := hex.EncodeToString(identityInt.Bytes())
		prekeyStr := hex.EncodeToString(prekeyInt.Bytes())

		formData := url.Values{
			"w":      {identityStr},
			"prekey": {prekeyStr},
		}

		res, _ := http.PostForm(static_urls[1]+"/register", formData)
		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		strs := strings.Split(string(text), "\n")

		if strs[0] == "Error" {
			fmt.Printf("%s", text)
		}
	}
}

func main() {

	var choice string

	fmt.Print("Enter Number of Queries to Perform: ")
	fmt.Scanln(&choice)
	queries, _ := strconv.Atoi(choice)

	fmt.Print("Enter Number of Warmup Queries: ")
	fmt.Scanln(&choice)
	warmups, _ := strconv.Atoi(choice)

	fmt.Print("Require Proof With Queries?: ")
	fmt.Scanln(&choice)

	proof := false
	if choice == "true" {
		proof = true
	}

	fmt.Print("Enter Number of Registrations to Run in Parallel: ")
	fmt.Scanln(&choice)
	registrations, _ := strconv.Atoi(choice)

	fmt.Println(queries, warmups, proof, registrations)
	go sendRegistrations(registrations)
	timeQueries(queries, warmups, proof)
}
