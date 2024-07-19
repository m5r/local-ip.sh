package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"local-ip.sh/utils"
)

type Account struct {
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
	Email        string
}

func (u *Account) GetEmail() string {
	return u.Email
}

func (u *Account) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func LoadAccount() *Account {
	jsonBytes, err := os.ReadFile(accountFilePath)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			RegisterAccount()
			return LoadAccount()
		}
		utils.Logger.Fatal().Err(err).Msg("Failed to load account from existing file")
	}

	account := &Account{}
	err = json.Unmarshal(jsonBytes, account)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to unmarshal account JSON file")
	}

	privKey, err := os.ReadFile(keyFilePath)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to read account's private key file")
	}

	account.key = decode(string(privKey))
	return account
}

func RegisterAccount() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to generate account key")
	}

	account := &Account{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(account)
	config.CADirURL = caDirUrl
	legoClient, err := lego.NewClient(config)
	if err != nil {
		utils.Logger.Fatal().Err(err).Str("CA Directory URL", config.CADirURL).Msg("Failed to initialize lego client")
	}

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		utils.Logger.Fatal().Err(err).Str("CA Directory URL", config.CADirURL).Msg("Failed to register account to ACME server")
	}
	if reg.Body.Status != "valid" {
		utils.Logger.Fatal().Err(err).Str("CA Directory URL", config.CADirURL).Msgf("Registration failed with status %s", reg.Body.Status)
	}

	utils.Logger.Debug().
		Str("CA Directory URL", config.CADirURL).
		Bool("TermsOfServiceAgreed", reg.Body.TermsOfServiceAgreed).
		Msg("Successfully registered account to ACME server")
	account.Registration = reg

	os.MkdirAll(filepath.Dir(keyFilePath), os.ModePerm)
	privKey := encode(privateKey)
	err = os.WriteFile(keyFilePath, []byte(privKey), 0o644)
	if err != nil {
		utils.Logger.Fatal().Err(err).Str("path", keyFilePath).Msg("Failed to write account's private key file")
	}

	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		utils.Logger.Fatal().Err(err).Msg("Failed to marshal account JSON file")
	}

	os.MkdirAll(filepath.Dir(accountFilePath), os.ModePerm)
	err = os.WriteFile(accountFilePath, jsonBytes, 0o600)
	if err != nil {
		utils.Logger.Fatal().Err(err).Str("path", accountFilePath).Msg("Failed to write account's JSON file")
	}
}

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	return string(pemEncoded)
}

func decode(pemEncoded string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return privateKey
}
