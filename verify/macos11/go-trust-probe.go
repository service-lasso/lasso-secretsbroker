package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Accepted                 bool       `json:"accepted"`
	Error                    string     `json:"error,omitempty"`
	ChainSha256              [][]string `json:"chainSha256"`
	RootsMode                string     `json:"rootsMode"`
	RepeatedConcurrentStable bool       `json:"repeatedConcurrentStable"`
	Calls                    int        `json:"calls"`
}

func fixtureBytes(root *os.Root, base, p string) ([]byte, error) {
	absolute, e := filepath.Abs(p)
	if e != nil {
		return nil, e
	}
	relative, e := filepath.Rel(base, absolute)
	if e != nil {
		return nil, e
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, errors.New("certificate outside fixture directory")
	}
	file, e := root.Open(relative)
	if e != nil {
		return nil, e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, 1048577))
	if e != nil {
		return nil, e
	}
	if len(b) > 1048576 {
		return nil, errors.New("certificate exceeds fixture size limit")
	}
	return b, nil
}
func cert(root *os.Root, base, p string) *x509.Certificate {
	b, e := fixtureBytes(root, base, p)
	if e != nil {
		panic(e)
	}
	c, e := x509.ParseCertificate(b)
	if e != nil {
		panic(e)
	}
	return c
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "https" {
		client := &http.Client{Timeout: 20 * time.Second}
		r, e := client.Get("https://github.com/")
		if e != nil {
			panic(e)
		}
		defer r.Body.Close()
		fmt.Printf("{\"liveTrustedHttps\":true,\"status\":%d,\"nativeRoots\":true}\n", r.StatusCode)
		return
	}
	if len(os.Args) < 5 {
		panic("host unix-time rootsDER-or-dash certDER...")
	}
	sec, e := strconv.ParseInt(os.Args[2], 10, 64)
	if e != nil {
		panic(e)
	}
	// The operator-selected leaf directory is the fixed fixture boundary for every
	// certificate in this invocation; roots/intermediates cannot escape it.
	leafPath, e := filepath.Abs(os.Args[4])
	if e != nil {
		panic(e)
	}
	base := filepath.Dir(leafPath)
	root, e := os.OpenRoot(base)
	if e != nil {
		panic(e)
	}
	defer root.Close()
	leaf := cert(root, base, os.Args[4])
	opts := x509.VerifyOptions{DNSName: os.Args[1], CurrentTime: time.Unix(sec, 0), Intermediates: x509.NewCertPool()}
	mode := "nil-native-host-roots"
	if os.Args[3] != "-" {
		opts.Roots = x509.NewCertPool()
		opts.Roots.AddCert(cert(root, base, os.Args[3]))
		mode = "custom-root-go-policy"
	}
	for _, p := range os.Args[5:] {
		opts.Intermediates.AddCert(cert(root, base, p))
	}
	verify := func() Result {
		chains, err := leaf.Verify(opts)
		r := Result{Accepted: err == nil, RootsMode: mode}
		if err != nil {
			r.Error = err.Error()
		}
		for _, chain := range chains {
			hashes := []string{}
			for _, c := range chain {
				h := sha256.Sum256(c.Raw)
				hashes = append(hashes, hex.EncodeToString(h[:]))
			}
			r.ChainSha256 = append(r.ChainSha256, hashes)
		}
		return r
	}
	baseline := verify()
	stable := true
	var mutex sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := verify()
			mutex.Lock()
			if !reflect.DeepEqual(r, baseline) {
				stable = false
			}
			mutex.Unlock()
		}()
	}
	wg.Wait()
	baseline.RepeatedConcurrentStable = stable
	baseline.Calls = 101
	b, e := json.Marshal(baseline)
	if e != nil {
		panic(e)
	}
	fmt.Println(string(b))
	if !stable {
		os.Exit(1)
	}
}
