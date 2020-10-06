/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/benjaminwyss/pythia"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bn256"
)

var identity string
var password string
var salt string
var proof bool

// queryCmd represents the query command
var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query the pythia blockchain service for a hardened password",
	Long: `Query the pythia blockchain service for a hardened password.
Make sure an identity is registered with the register command before calling query. 
Sample usage: query -x password -t salt
With proof:   query -x password -t salt -p`,
	Run: func(cmd *cobra.Command, args []string) {
		if identity != "" {
			viper.Set("identity", identity)
		}

		viper.SetConfigType("yaml")
		viper.SetConfigFile(".pythiacli.yaml")
		viper.WriteConfig()

		blindHash, rInv := pythia.HashBlind(password)
		x := hex.EncodeToString(blindHash)

		w := viper.GetString("identity")

		p := "0"
		if proof {
			p = "1"
		}

		formData := url.Values{
			"w": {w},
			"x": {x},
			"t": {salt},
			"p": {p},
		}

		res, err := http.PostForm("http://fennel.ittc.ku.edu:8080/query", formData)

		if err != nil {
			fmt.Printf("Error connecting to intermediate pythia server. %s\n", err.Error())
		}

		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		strs := strings.Split(string(text), "\n")
		if strs[0] != "Error" {

			if proof {
				if strs[1] != viper.GetString("pubkey") {
					fmt.Printf("Error\nPublic key provided by proof does not match stored pythia public key\n")
					return
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
				} else {
					gt := new(bn256.GT)
					gt.Unmarshal(blindResult)
					resultBytes := pythia.UnblindGT(gt, rInv)
					result := hex.EncodeToString(resultBytes)

					fmt.Printf("%s\n", result)

				}
			} else {
				resultBytes, _ := hex.DecodeString(strs[0])
				gt := new(bn256.GT)
				gt.Unmarshal(resultBytes)

				resultBytes = pythia.UnblindGT(gt, rInv)
				result := hex.EncodeToString(resultBytes)

				fmt.Printf("%s\n", result)
			}

		} else {
			for _, v := range strs {
				fmt.Println(v)
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(queryCmd)

	queryCmd.PersistentFlags().StringVarP(&identity, "identity", "w", "", "override stored identity string")

	queryCmd.Flags().StringVarP(&password, "password", "x", "", "password string")
	queryCmd.MarkFlagRequired("password")

	queryCmd.Flags().StringVarP(&salt, "salt", "t", "", "salt string")
	queryCmd.MarkFlagRequired("salt")

	queryCmd.Flags().BoolVarP(&proof, "proof", "p", false, "request zero knowledge proof")
}
