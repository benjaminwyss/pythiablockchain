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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var email string

// registerEmailCmd represents the registerEmail command
var registerEmailCmd = &cobra.Command{
	Use:   "registerEmail",
	Short: "Register an email to be able to receieve authentication tokens for key rotation",
	Long: `Register an email to be able to receieve authentication tokens for key rotation
This command registeres the provided email with your identity on the pythia blockchain service`,
	Run: func(cmd *cobra.Command, args []string) {
		if identity != "" {
			viper.Set("identity", identity)
		}

		viper.SetConfigType("yaml")
		viper.SetConfigFile(".pythiacli.yaml")
		viper.WriteConfig()

		w := viper.GetString("identity")

		formData := url.Values{
			"w":     {w},
			"email": {email},
		}

		res, err := http.PostForm("http://fennel.ittc.ku.edu:8080/registerEmail", formData)

		if err != nil {
			fmt.Printf("Error connecting to intermediate pythia server. %s\n", err.Error())
		}

		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		strs := strings.Split(string(text), "\n")
		if strs[0] != "Error" {
			fmt.Printf("Email successfully registered with pythia blockchain service.\n")
		} else {
			for _, v := range strs {
				fmt.Println(v)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(registerEmailCmd)

	registerEmailCmd.PersistentFlags().StringVarP(&identity, "identity", "w", "", "override stored identity string")

	registerEmailCmd.Flags().StringVarP(&email, "email", "e", "", "email string")
	registerEmailCmd.MarkFlagRequired("email")
}
