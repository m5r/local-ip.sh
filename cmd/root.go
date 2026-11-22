package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"local-ip.sh/app"
	"local-ip.sh/certs"
	"local-ip.sh/utils"
)

var command = &cobra.Command{
	Use: "local-ip.sh",
	Run: func(cmd *cobra.Command, args []string) {
		loadEnvironment()

		err := utils.InitLogger(utils.LogOptions{
			Level:  viper.GetString("log-level"),
			Format: viper.GetString("log-format"),
			File:   viper.GetString("log-file"),
		})
		if err != nil {
			utils.Logger.Fatal().Err(err).Msg("Invalid logging configuration")
		}

		cfg, err := config()
		if err != nil {
			utils.Logger.Fatal().Err(err).Msg("Invalid configuration")
		}
		a, err := app.New(cfg)
		if err != nil {
			utils.Logger.Fatal().Err(err).Msg("Failed to start")
		}

		ctx, stop := shutdownContext()
		defer stop()
		onRenewSignal(ctx, utils.Logger, a.RenewCertificates)

		if err := a.Run(ctx); err != nil {
			utils.Logger.Fatal().Err(err).Msg("Stopped")
		}
		utils.Logger.Info().Msg("Shut down")
	},
}

// loadEnvironment makes every option readable from an environment variable: XIP_ followed by the flag's name in upper case, with "-" turned into "_".
func loadEnvironment() {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("XIP")
	viper.AutomaticEnv()
}

// shutdownContext is cancelled by the first SIGINT or SIGTERM.
func shutdownContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Once the first signal has started the shutdown, the registration is released so that a second signal has its default effect and ends the process at once, should the shutdown hang.
	context.AfterFunc(ctx, stop)
	return ctx, stop
}

// config turns the options into an app.Config. It parses each option into its type and fails on a value that does not parse; what a value means (a valid domain, email or name server) is checked by the packages that depend on it.
func config() (app.Config, error) {
	// Fly only delivers UDP to a socket bound to fly-global-services, and TCP to a socket on any interface.
	dnsUDPHost := ""
	if os.Getenv("FLY_APP_NAME") != "" {
		dnsUDPHost = "fly-global-services"
	}

	staging, err := boolOption("staging")
	if err != nil {
		return app.Config{}, err
	}
	directoryURL := certs.LetsEncryptProduction
	if staging {
		directoryURL = certs.LetsEncryptStaging
	}

	ports := map[string]string{}
	for _, name := range []string{"dns-port", "http-port", "https-port"} {
		port, err := portOption(name)
		if err != nil {
			return app.Config{}, err
		}
		ports[name] = port
	}

	var nameServers []string
	if list := viper.GetString("nameservers"); list != "" {
		nameServers = strings.Split(list, ",")
	}

	return app.Config{
		Domain:        viper.GetString("domain"),
		Email:         viper.GetString("email"),
		NameServers:   nameServers,
		ZoneFile:      viper.GetString("zone-file"),
		DNSUDPAddress: net.JoinHostPort(dnsUDPHost, ports["dns-port"]),
		DNSTCPAddress: ":" + ports["dns-port"],
		HTTPAddress:   ":" + ports["http-port"],
		HTTPSAddress:  ":" + ports["https-port"],
		StateDir:      viper.GetString("state-dir"),
		DirectoryURL:  directoryURL,
		ACMEProfile:   viper.GetString("acme-profile"),
		Region:        os.Getenv("FLY_REGION"),
		Logger:        utils.Logger,
	}, nil
}

// boolOption parses the effective text of a boolean option, whether it comes from the flag, the environment or the default.
func boolOption(name string) (bool, error) {
	text := viper.GetString(name)
	value, err := strconv.ParseBool(text)
	if err != nil {
		return false, invalidOption(name, text, err)
	}
	return value, nil
}

// portOption parses the effective text of a port option, from the flag or the environment alike, as a decimal number from 0 to 65535: a leading zero is decimal (010 is port 10), and neither a base prefix nor a service name such as "ssh", which net.Listen would take, is accepted. The port flags are strings so that this is the only parser.
func portOption(name string) (string, error) {
	text := viper.GetString(name)
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return "", invalidOption(name, text, err)
	}
	return strconv.FormatUint(port, 10), nil
}

// invalidOption names the option in both of its spellings.
func invalidOption(name, text string, err error) error {
	return fmt.Errorf("invalid value %q for --%s / XIP_%s: %w", text, name, strings.ToUpper(strings.ReplaceAll(name, "-", "_")), err)
}

func Execute() {
	if err := defineFlags(command); err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to bind the command line flags")
	}

	if err := command.Execute(); err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to run local-ip.sh")
	}
}

// defineFlags declares the command line flags on cmd and binds each one to viper under its own name.
func defineFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.String("log-level", utils.DefaultLogLevel, "Log level: trace, debug, info, warn or error")
	flags.String("log-format", utils.DefaultLogFormat, "Log format: auto, json or console (auto is console on a terminal, json otherwise)")
	flags.String("log-file", "", "Path of an additional rotating log file (optional)")
	flags.String("dns-port", "53", "Port for the DNS server")
	flags.String("http-port", "80", "Port for the HTTP server")
	flags.String("https-port", "443", "Port for the HTTPS server")
	flags.Bool("staging", false, "Enable to use the Let's Encrypt staging environment to obtain certificates")
	flags.String("domain", "", "Root domain (required)")
	flags.String("email", "", "ACME account email address (required)")
	flags.String("nameservers", "", "List of nameservers separated by commas (required)")
	flags.String("zone-file", "", "Path to a zone file declaring delegations (optional)")
	flags.String("state-dir", "./state", "Directory for the ACME account and the certificates")
	flags.String("acme-profile", "", "ACME certificate profile to request (optional, the certificate authority chooses by default)")
	return viper.BindPFlags(flags)
}
