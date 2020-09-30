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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bn256"
)

var authToken string

// genUpdateCmd represents the genUpdate command
var genUpdateCmd = &cobra.Command{
	Use:   "genUpdate",
	Short: "Request a key rotation update token from the pythia blockchain service",
	Long: `Request a key roation update token from the pythia blockchain service.
Use this if you believe that your password database has been compromised.
An authorization token from the genAuth command is required.
This command rotates the pythia secret key associated with your identity and stores an update token in the pythiacli config file.
You can then update existing password hashes to the new secret key with the applyUpdate command`,
	Run: func(cmd *cobra.Command, args []string) {
		if identity != "" {
			viper.Set("identity", identity)
		}

		viper.SetConfigType("yaml")
		viper.SetConfigFile(".pythiacli.yaml")
		viper.WriteConfig()

		prekeyInt, _ := rand.Int(rand.Reader, bn256.Order)

		identity := viper.GetString("identity")
		prekeyStr := hex.EncodeToString(prekeyInt.Bytes())

		formData := url.Values{
			"w":         {identity},
			"prekey":    {prekeyStr},
			"authToken": {authToken},
		}

		res, err := http.PostForm("http://fennel.ittc.ku.edu:8080/genUpdate", formData)

		if err != nil {
			fmt.Printf("Error connecting to intermediate pythia server. %s\n", err.Error())
		}

		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		strs := strings.Split(string(text), "\n")
		if strs[0] != "Error" {
			updateToken := strs[0]
			pubkey := strs[1]

			viper.Set("pubkey", pubkey)
			viper.Set("updateToken", updateToken)

			viper.SetConfigType("yaml")
			viper.SetConfigFile(".pythiacli.yaml")
			viper.WriteConfig()

			fmt.Printf("Update token successfully generated and stored.\nPythia public key and secret key updated.\nUse applyUpdate command to update existing password hashes")

		} else {
			for _, v := range strs {
				fmt.Println(v)
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(genUpdateCmd)

	genUpdateCmd.PersistentFlags().StringVarP(&identity, "identity", "w", "", "override stored identity string")

	genUpdateCmd.Flags().StringVarP(&authToken, "auth", "a", "", "authorization token string")
	genUpdateCmd.MarkFlagRequired("auth")

}
