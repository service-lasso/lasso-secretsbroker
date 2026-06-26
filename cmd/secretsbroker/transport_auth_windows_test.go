//go:build windows

package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestWindowsNamedPipeClientAuthorization(t *testing.T) {
	if !windowsNamedPipeClientAuthorized(windowsClientIdentity{UserSID: "S-1-5-21-1000"}, "s-1-5-21-1000") {
		t.Fatalf("same user SID should be authorized")
	}
	if !windowsNamedPipeClientAuthorized(windowsClientIdentity{UserSID: "S-1-5-18", IsLocalSystem: true}, "S-1-5-21-1000") {
		t.Fatalf("LocalSystem should be authorized")
	}
	if !windowsNamedPipeClientAuthorized(windowsClientIdentity{UserSID: "S-1-5-21-1001", IsBuiltinAdminMember: true}, "S-1-5-21-1000") {
		t.Fatalf("enabled builtin administrator member should be authorized")
	}
	if windowsNamedPipeClientAuthorized(windowsClientIdentity{UserSID: "S-1-5-21-1001"}, "S-1-5-21-1000") {
		t.Fatalf("untrusted different user SID should be rejected")
	}
}

func TestWindowsNamedPipeSecurityDescriptorContainsCurrentUser(t *testing.T) {
	sid, err := currentWindowsUserSIDString()
	if err != nil {
		t.Fatal(err)
	}
	sddl := windowsNamedPipeSecurityDescriptor(sid)
	for _, want := range []string{"D:P", "SY", "BA", sid} {
		if !strings.Contains(sddl, want) {
			t.Fatalf("security descriptor %q missing %q", sddl, want)
		}
	}
}

func TestWindowsTokenIdentityIncludesCurrentUser(t *testing.T) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close() //nolint:errcheck

	identity, err := windowsTokenIdentity(token)
	if err != nil {
		t.Fatal(err)
	}
	currentSID, err := currentWindowsUserSIDString()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(identity.UserSID, currentSID) {
		t.Fatalf("identity SID = %q, want %q", identity.UserSID, currentSID)
	}
}

func TestWindowsNamedPipeListenerAcceptsSameUserClient(t *testing.T) {
	path := `\\.\pipe\service-lasso-secretsbroker-test-` + time.Now().Format("20060102150405.000000000")
	binding := serveTransportBinding{Kind: "windows-named-pipe", Network: "windows-named-pipe", Address: path, DisplayAddress: path}
	ln, cleanup, err := listenForTransport(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		_ = conn.Close()
		accepted <- nil
	}()

	timeout := 2 * time.Second
	client, err := winio.DialPipe(path, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for same-user Windows named-pipe peer")
	}
}

func TestWindowsNamedPipeTransportServesHTTP(t *testing.T) {
	path := `\\.\pipe\service-lasso-secretsbroker-http-test-` + time.Now().Format("20060102150405.000000000")
	binding := serveTransportBinding{Kind: "windows-named-pipe", Network: "windows-named-pipe", Address: path, DisplayAddress: path}
	ln, cleanup, err := listenForTransport(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	state := "ready"
	server := &http.Server{Handler: newHandler(runtimeState{state: &state}, nil, localAPISecurity{}), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(ln)
		if err == http.ErrServerClosed {
			err = nil
		}
		done <- err
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()

	timeout := 2 * time.Second
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return winio.DialPipe(path, &timeout)
		},
	}}
	res, err := client.Get("http://secretsbroker.local/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d", res.StatusCode)
	}
}

func TestAuthorizeWindowsNamedPipeConnRejectsNonPipeConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := authorizeWindowsNamedPipeConn(server, "S-1-5-21-1000"); err == nil {
		t.Fatalf("expected non-pipe connection rejection")
	}
}
