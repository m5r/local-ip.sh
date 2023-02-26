package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type Account struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
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
		log.Fatal(err)
	}
	account := &Account{}
	err = json.Unmarshal(jsonBytes, account)
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := os.ReadFile(keyFilePath)
	if err != nil {
		log.Fatal(err)
	}
	privateKey := decode(string(privKey))

	account.key = privateKey
	return account
}

func RegisterAccount() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	account := &Account{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(account)
	config.CADirURL = caDirUrl
	legoClient, err := lego.NewClient(config)

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if reg.Body.Status != "valid" {
		log.Fatalf("registration failed with status %s", reg.Body.Status)
	}
	log.Println(reg.Body.TermsOfServiceAgreed)
	account.Registration = reg

	os.MkdirAll(filepath.Dir(keyFilePath), os.ModePerm)
	privKey := encode(privateKey)
	err = os.WriteFile(keyFilePath, []byte(privKey), 0o644)
	if err != nil {
		log.Fatal(err)
	}

	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	os.MkdirAll(filepath.Dir(accountFilePath), os.ModePerm)
	err = os.WriteFile(accountFilePath, jsonBytes, 0o600)
	if err != nil {
		log.Fatal(err)
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
