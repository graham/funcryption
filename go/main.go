package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/fernet/fernet-go"
)

type Service struct {
	InnerSecret fernet.Key
	OuterSecret fernet.Key
}

func (s Service) Magic(claims []string, service_name string) []byte {
	payload := struct {
		Claims  []string `json:"claims"`
		Service string   `json:"service"`
	}{
		Claims:  claims,
		Service: service_name,
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	tok, err := fernet.EncryptAndSign(bytes, &s.InnerSecret)
	if err != nil {
		panic(err)
	}

	return tok
}

func (s Service) DecryptToken(d []byte) map[string]interface{} {
	encrypted_magic := fernet.VerifyAndDecrypt(d, time.Duration(100*time.Hour), []*fernet.Key{&s.OuterSecret})

	if encrypted_magic == nil {
		return nil
	}

	payload := fernet.VerifyAndDecrypt(encrypted_magic, time.Duration(100*time.Hour), []*fernet.Key{&s.InnerSecret})

	var ret map[string]interface{}

	err := json.Unmarshal(payload, &ret)

	if err != nil {
		return nil
	}

	return ret
}

type Client struct {
	Secret fernet.Key
	Magic  []byte
}

func (c Client) ApiKey() []byte {
	tok, err := fernet.EncryptAndSign(c.Magic, &c.Secret)
	if err != nil {
		panic(err)
	}

	return tok
}

func main() {
	var inner_secret fernet.Key
	var outer_secret fernet.Key

	inner_secret.Generate()
	outer_secret.Generate()

	serv := Service{
		InnerSecret: inner_secret,
		OuterSecret: outer_secret,
	}

	magic := serv.Magic([]string{"read", "write"}, "graham")

	client := Client{
		Secret: outer_secret,
		Magic:  magic,
	}

	api_key := client.ApiKey()

	finally := serv.DecryptToken(api_key)

	fmt.Printf("%s\n", finally)
}
