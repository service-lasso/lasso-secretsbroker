//go:build windows

package main

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows"
)

type windowsNamedPipeListener struct {
	net.Listener
	allowedUserSID string
}

type windowsPipeConnHandle interface {
	Fd() uintptr
}

type windowsClientIdentity struct {
	UserSID              string
	IsLocalSystem        bool
	IsBuiltinAdminMember bool
}

func authenticatedWindowsNamedPipeListener(ln net.Listener, allowedUserSID string) net.Listener {
	return &windowsNamedPipeListener{Listener: ln, allowedUserSID: allowedUserSID}
}

func (l *windowsNamedPipeListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		identity, err := authorizeWindowsNamedPipeConn(conn, l.allowedUserSID)
		if err != nil {
			_ = conn.Close()
			continue
		}
		return withTransportPeerIdentityConn(conn, identity), nil
	}
}

func authorizeWindowsNamedPipeConn(conn net.Conn, allowedUserSID string) (transportPeerIdentity, error) {
	fdConn, ok := conn.(windowsPipeConnHandle)
	if !ok {
		return transportPeerIdentity{}, fmt.Errorf("windows-named-pipe transport connection is %T, want handle-bearing pipe connection", conn)
	}
	identity, err := windowsNamedPipeClientIdentity(windows.Handle(fdConn.Fd()))
	if err != nil {
		return transportPeerIdentity{}, err
	}
	if !windowsNamedPipeClientAuthorized(identity, allowedUserSID) {
		return transportPeerIdentity{}, fmt.Errorf("windows-named-pipe transport rejected local peer sid")
	}
	return transportPeerIdentity{Kind: "windows-sid", Subject: identity.UserSID}, nil
}

func windowsNamedPipeClientAuthorized(identity windowsClientIdentity, allowedUserSID string) bool {
	allowedUserSID = strings.TrimSpace(allowedUserSID)
	if allowedUserSID != "" && strings.EqualFold(identity.UserSID, allowedUserSID) {
		return true
	}
	return identity.IsLocalSystem || identity.IsBuiltinAdminMember
}

func windowsNamedPipeClientIdentity(pipe windows.Handle) (windowsClientIdentity, error) {
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		return windowsClientIdentity{}, fmt.Errorf("windows-named-pipe transport cannot identify client process: %w", err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return windowsClientIdentity{}, fmt.Errorf("windows-named-pipe transport cannot inspect client process identity: %w", err)
	}
	defer windows.CloseHandle(process) //nolint:errcheck

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return windowsClientIdentity{}, fmt.Errorf("windows-named-pipe transport cannot inspect client token: %w", err)
	}
	defer token.Close() //nolint:errcheck

	return windowsTokenIdentity(token)
}

func windowsTokenIdentity(token windows.Token) (windowsClientIdentity, error) {
	userSID, err := windowsTokenUserSIDString(token)
	if err != nil {
		return windowsClientIdentity{}, err
	}
	localSystem, err := windowsSIDIsWellKnown(userSID, windows.WinLocalSystemSid)
	if err != nil {
		return windowsClientIdentity{}, err
	}
	admin, err := windowsTokenHasEnabledGroup(token, windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return windowsClientIdentity{}, err
	}
	return windowsClientIdentity{
		UserSID:              userSID,
		IsLocalSystem:        localSystem,
		IsBuiltinAdminMember: admin,
	}, nil
}

func currentWindowsUserSIDString() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("windows-named-pipe transport cannot inspect server identity: %w", err)
	}
	defer token.Close() //nolint:errcheck
	return windowsTokenUserSIDString(token)
}

func windowsTokenUserSIDString(token windows.Token) (string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("windows-named-pipe transport cannot read token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return "", fmt.Errorf("windows-named-pipe transport token user is missing")
	}
	return user.User.Sid.String(), nil
}

func windowsTokenHasEnabledGroup(token windows.Token, sidType windows.WELL_KNOWN_SID_TYPE) (bool, error) {
	want, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		return false, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, fmt.Errorf("windows-named-pipe transport cannot read token groups: %w", err)
	}
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || !group.Sid.Equals(want) {
			continue
		}
		if group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			return false, nil
		}
		return group.Attributes&windows.SE_GROUP_ENABLED != 0, nil
	}
	return false, nil
}

func windowsSIDIsWellKnown(sidString string, sidType windows.WELL_KNOWN_SID_TYPE) (bool, error) {
	sid, err := windows.StringToSid(sidString)
	if err != nil {
		return false, err
	}
	want, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		return false, err
	}
	return sid.Equals(want), nil
}

func windowsNamedPipeSecurityDescriptor(userSID string) string {
	userSID = strings.TrimSpace(userSID)
	if userSID == "" {
		return "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	}
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", userSID)
}
