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

// genAuthCmd represents the genAuth command
var genAuthCmd = &cobra.Command{
	Use:   "genAuth",
	Short: "Generate an authentication token for key rotation and send it to your registered email",
	Long: `Generate an authentication token for key rotation and send it to your registered email
This command requires an email to be previously registered with the registerEmail command`,
	Run: func(cmd *cobra.Command, args []string) {
		if identity != "" {
			viper.Set("identity", identity)
		}

		viper.SetConfigType("yaml")
		viper.SetConfigFile(".pythiacli.yaml")
		viper.WriteConfig()

		w := viper.GetString("identity")

		formData := url.Values{
			"w": {w},
		}

		res, err := http.PostForm("http://fennel.ittc.ku.edu:8080/genAuth", formData)

		if err != nil {
			fmt.Printf("Error connecting to intermediate pythia server. %s\n", err.Error())
		}

		text, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		strs := strings.Split(string(text), "\n")
		if strs[0] != "Error" {
			if strs[0] == "202" {
				fmt.Printf("Authorization token sucessfully sent. Check the inbox your registered email address")
			} else {
				fmt.Printf("Error sending email. %s\n%s\n%s", strs[0], strs[1], strs[2])
			}
		} else {
			for _, v := range strs {
				fmt.Println(v)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(genAuthCmd)

	genAuthCmd.PersistentFlags().StringVarP(&identity, "identity", "w", "", "override stored identity string")
}
