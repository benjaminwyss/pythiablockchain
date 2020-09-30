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
	"math/big"

	"github.com/benjaminwyss/pythia"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var updateToken string
var hash string

// applyUpdateCmd represents the applyUpdate command
var applyUpdateCmd = &cobra.Command{
	Use:   "applyUpdate",
	Short: "Apply a generated update token to reencrypt an existing password hash under a newly rotated key",
	Long: `Apply a generated update token to reencrypt an existing password hash under a newly rotated key.
Sample usage:          applyUpdate -z hash
Override update token: applyUpdate -z hash -u updateToken`,
	Run: func(cmd *cobra.Command, args []string) {
		token := viper.GetString("updateToken")
		if updateToken != "" {
			token = updateToken
		}

		hashBytes, _ := hex.DecodeString(hash)
		tokenBytes, _ := hex.DecodeString(token)

		tokenInt := new(big.Int).SetBytes(tokenBytes)

		updatedHashBytes := pythia.ApplyUpdateToken(hashBytes, tokenInt)
		updatedHash := hex.EncodeToString(updatedHashBytes)

		fmt.Printf("\n%s\n", updatedHash)
	},
}

func init() {
	rootCmd.AddCommand(applyUpdateCmd)

	applyUpdateCmd.PersistentFlags().StringVarP(&updateToken, "updateToken", "u", "", "override stored update token")

	applyUpdateCmd.Flags().StringVarP(&hash, "hash", "z", "", "pythia-hardened password hash string")
	applyUpdateCmd.MarkFlagRequired("hash")
}
