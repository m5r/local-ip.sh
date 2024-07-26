package utils

import (
	"github.com/spf13/viper"
)

type config struct {
	DnsPort   uint `mapstructure:"dns-port"`
	HttpPort  uint `mapstructure:"http-port"`
	HttpsPort uint `mapstructure:"https-port"`
	Domain    string
	Email     string

	NameServers     []string
	CADirURL        string
	AccountFilePath string
	KeyFilePath     string
}

var conf = &config{}

func InitConfig() *config {
	viper.Unmarshal(conf)
	return conf
}

func GetConfig() *config {
	return conf
}
