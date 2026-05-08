package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const masterKeyVersion = "v1"

type keyMaterial struct {
	Value  string
	Source string
}

type keyStatusResponse struct {
	ServiceID  string `json:"serviceId"`
	APIVersion string `json:"apiVersion"`
	Available  bool   `json:"available"`
	KeyID      string `json:"keyId"`
	KeyVersion string `json:"keyVersion"`
	Source     string `json:"source"`
	State      string `json:"state"`
}

type keyGenerateResponse struct {
	ServiceID  string `json:"serviceId"`
	APIVersion string `json:"apiVersion"`
	KeyID      string `json:"keyId"`
	KeyVersion string `json:"keyVersion"`
	MasterKey  string `json:"masterKey"`
	Warning    string `json:"warning"`
}

func runKey(args []string) error {
	if len(args) == 0 {
		return printKeyStatus(args)
	}
	switch args[0] {
	case "status":
		return printKeyStatus(args[1:])
	case "generate":
		return printGeneratedKey()
	case "rotate":
		return runKeyRotate(args[1:])
	default:
		return fmt.Errorf("unknown key command %q", args[0])
	}
}

func printKeyStatus(args []string) error {
	fs := flag.NewFlagSet("key status", flag.ContinueOnError)
	masterKey := fs.String("master-key", getenvDefault("SECRETSBROKER_MASTER_KEY", ""), "local development master key")
	masterKeyFile := fs.String("master-key-file", getenvDefault("SECRETSBROKER_MASTER_KEY_FILE", ""), "file containing portable master key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadKeyMaterial(*masterKey, *masterKeyFile)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(keyStatus(material))
}

func printGeneratedKey() error {
	key, err := generatePortableMasterKey()
	if err != nil {
		return err
	}
	res := keyGenerateResponse{
		ServiceID:  serviceID,
		APIVersion: apiVersion,
		KeyID:      masterKeyID(key),
		KeyVersion: masterKeyVersion,
		MasterKey:  key,
		Warning:    "Store this portable master key securely. It can decrypt local vault payloads.",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func loadKeyMaterial(flagValue, filePath string) (keyMaterial, error) {
	if strings.TrimSpace(flagValue) != "" {
		return keyMaterial{Value: strings.TrimSpace(flagValue), Source: "flag/env"}, nil
	}
	if strings.TrimSpace(filePath) != "" {
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			return keyMaterial{}, err
		}
		value := strings.TrimSpace(string(bytes))
		if value != "" {
			return keyMaterial{Value: value, Source: "file"}, nil
		}
	}
	return keyMaterial{Source: "none"}, errLocked
}

func keyStatus(material keyMaterial) keyStatusResponse {
	available := strings.TrimSpace(material.Value) != ""
	state := "locked"
	keyID := ""
	keyVersion := ""
	if available {
		state = "ready"
		keyID = masterKeyID(material.Value)
		keyVersion = masterKeyVersion
	}
	source := material.Source
	if source == "" {
		source = "none"
	}
	return keyStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Available: available, KeyID: keyID, KeyVersion: keyVersion, Source: source, State: state}
}

func generatePortableMasterKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func masterKeyID(masterKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(masterKey)))
	return "mk-" + hex.EncodeToString(sum[:])[:16]
}
