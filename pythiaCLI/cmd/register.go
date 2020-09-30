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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/viper"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bn256"
)

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new identity with the pythia blockchain service",
	Long: `Register a new identity with the pythia blockchain service.
If this command is successful, the pythia service will respond with both an identity string and a pythia public key for verification.
These items will be stored in the pythiacli config file.`,
	Run: func(cmd *cobra.Command, args []string) {
		identityInt, _ := rand.Int(rand.Reader, bn256.Order)
		prekeyInt, _ := rand.Int(rand.Reader, bn256.Order)

		identityStr := hex.EncodeToString(identityInt.Bytes())
		prekeyStr := hex.EncodeToString(prekeyInt.Bytes())

		formData := url.Values{
			"w":      {identityStr},
			"prekey": {prekeyStr},
		}

		res, err := http.PostForm("http://fennel.ittc.ku.edu:8080/register", formData)

		if err != nil {
			fmt.Printf("Error connecting to intermediate pythia server. %s\n", err.Error())
		}

		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		strs := strings.Split(string(text), "\n")
		if strs[0] != "Error" {
			pubkey := strs[0]

			viper.Set("identity", identityStr)
			viper.Set("pubkey", pubkey)

			viper.SetConfigType("yaml")
			viper.SetConfigFile(".pythiacli.yaml")
			viper.WriteConfig()

			fmt.Printf("Identity successfully registered\n")

		} else {
			for _, v := range strs {
				fmt.Println(v)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(registerCmd)
}
