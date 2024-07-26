package cmd

import (
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-acme/lego/v4/lego"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"local-ip.sh/certs"
	"local-ip.sh/http"
	"local-ip.sh/utils"
	"local-ip.sh/xip"
)

var command = &cobra.Command{
	Use: "local-ip.sh",
	PreRun: func(cmd *cobra.Command, args []string) {
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.SetEnvPrefix("XIP")
		viper.AutomaticEnv()

		email := viper.GetString("Email")
		_, err := mail.ParseAddress(email)
		if err != nil {
			utils.Logger.Fatal().Err(err).Msg("Invalid email address")
		}

		domain := viper.GetString("Domain")
		if !govalidator.IsDNSName(domain) {
			utils.Logger.Fatal().Err(err).Msg("Invalid domain")
		}

		nameservers := strings.Split(viper.GetString("nameservers"), ",")
		for _, ns := range nameservers {
			if !govalidator.IsIPv4(ns) {
				utils.Logger.Fatal().Err(err).Str("ns", ns).Msg("Invalid name server")
			}
		}
		viper.Set("NameServers", nameservers)

		staging := viper.GetBool("staging")
		var caDir string
		if staging {
			caDir = lego.LEDirectoryStaging
		} else {
			caDir = lego.LEDirectoryProduction
		}
		viper.Set("CADirURL", caDir)

		parsedCaDirUrl, _ := url.Parse(caDir)
		caDirHostname := parsedCaDirUrl.Hostname()
		viper.Set("AccountFilePath", fmt.Sprintf("./.lego/accounts/%s/%s/account.json", caDirHostname, email))
		viper.Set("KeyFilePath", fmt.Sprintf("./.lego/accounts/%s/%s/keys/%s.key", caDirHostname, email, email))

		utils.InitConfig()
	},
	Run: func(cmd *cobra.Command, args []string) {
		n := xip.NewXip()

		go func() {
			// try to obtain certificates once the DNS server is accepting requests
			account := certs.LoadAccount()
			certsClient := certs.NewCertsClient(n, account)

			time.Sleep(5 * time.Second)
			certsClient.RequestCertificates()

			for {
				// afterwards, try to renew certificates once a day
				time.Sleep(24 * time.Hour)
				certsClient.RequestCertificates()
			}
		}()

		go http.ServeHttp()

		n.StartServer()
	},
}

func Execute() {
	command.Flags().Uint("dns-port", 53, "Port for the DNS server")
	viper.BindPFlag("dns-port", command.Flags().Lookup("dns-port"))

	command.Flags().Uint("http-port", 80, "Port for the HTTP server")
	viper.BindPFlag("http-port", command.Flags().Lookup("http-port"))

	command.Flags().Uint("https-port", 443, "Port for the HTTPS server")
	viper.BindPFlag("https-port", command.Flags().Lookup("https-port"))

	command.Flags().Bool("staging", false, "Enable to use the Let's Encrypt staging environment to obtain certificates")
	viper.BindPFlag("staging", command.Flags().Lookup("staging"))

	command.Flags().String("domain", "", "Root domain (required)")
	viper.BindPFlag("domain", command.Flags().Lookup("domain"))

	command.Flags().String("email", "", "ACME account email address (required)")
	viper.BindPFlag("email", command.Flags().Lookup("email"))

	command.Flags().String("nameservers", "", "List of nameservers separated by commas (required)")
	viper.BindPFlag("nameservers", command.Flags().Lookup("nameservers"))

	if err := command.Execute(); err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to run local-ip.sh")
	}
}
