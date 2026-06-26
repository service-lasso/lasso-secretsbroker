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
	policy windowsNamedPipeAccessPolicy
}

type windowsPipeConnHandle interface {
	Fd() uintptr
}

type windowsClientIdentity struct {
	UserSID              string
	IsLocalSystem        bool
	IsBuiltinAdminMember bool
}

func authenticatedWindowsNamedPipeListener(ln net.Listener, policy windowsNamedPipeAccessPolicy) net.Listener {
	return &windowsNamedPipeListener{Listener: ln, policy: normalizeWindowsNamedPipeAccessPolicy(policy)}
}

func (l *windowsNamedPipeListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		identity, err := authorizeWindowsNamedPipeConn(conn, l.policy)
		if err != nil {
			_ = conn.Close()
			continue
		}
		return withTransportPeerIdentityConn(conn, identity), nil
	}
}

func authorizeWindowsNamedPipeConn(conn net.Conn, policy windowsNamedPipeAccessPolicy) (transportPeerIdentity, error) {
	fdConn, ok := conn.(windowsPipeConnHandle)
	if !ok {
		return transportPeerIdentity{}, fmt.Errorf("windows-named-pipe transport connection is %T, want handle-bearing pipe connection", conn)
	}
	identity, err := windowsNamedPipeClientIdentity(windows.Handle(fdConn.Fd()))
	if err != nil {
		return transportPeerIdentity{}, err
	}
	if !windowsNamedPipeClientAuthorized(identity, policy) {
		return transportPeerIdentity{}, fmt.Errorf("windows-named-pipe transport rejected local peer sid")
	}
	return transportPeerIdentity{Kind: "windows-sid", Subject: identity.UserSID}, nil
}

func windowsNamedPipeClientAuthorized(identity windowsClientIdentity, policy windowsNamedPipeAccessPolicy) bool {
	policy = normalizeWindowsNamedPipeAccessPolicy(policy)
	for _, sid := range policy.AllowedUserSIDs {
		if strings.EqualFold(identity.UserSID, sid) {
			return true
		}
	}
	if identity.IsLocalSystem && policy.AllowLocalSystem {
		return true
	}
	return identity.IsBuiltinAdminMember && policy.AllowBuiltinAdmins
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

func windowsNamedPipeAccessPolicyWithServerSID(policy windowsNamedPipeAccessPolicy, serverUserSID string) windowsNamedPipeAccessPolicy {
	policy = normalizeWindowsNamedPipeAccessPolicy(policy)
	serverUserSID = strings.TrimSpace(serverUserSID)
	if serverUserSID != "" {
		policy.AllowedUserSIDs = append(policy.AllowedUserSIDs, serverUserSID)
	}
	return normalizeWindowsNamedPipeAccessPolicy(policy)
}

func normalizeWindowsNamedPipeAccessPolicy(policy windowsNamedPipeAccessPolicy) windowsNamedPipeAccessPolicy {
	seen := map[string]struct{}{}
	allowed := make([]string, 0, len(policy.AllowedUserSIDs))
	for _, sid := range policy.AllowedUserSIDs {
		sid = strings.TrimSpace(sid)
		if sid == "" {
			continue
		}
		key := strings.ToLower(sid)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		allowed = append(allowed, sid)
	}
	policy.AllowedUserSIDs = allowed
	return policy
}

func windowsNamedPipeSecurityDescriptor(policy windowsNamedPipeAccessPolicy) string {
	policy = normalizeWindowsNamedPipeAccessPolicy(policy)
	aces := []string{}
	if policy.AllowLocalSystem {
		aces = append(aces, "(A;;GA;;;SY)")
	}
	if policy.AllowBuiltinAdmins {
		aces = append(aces, "(A;;GA;;;BA)")
	}
	for _, sid := range policy.AllowedUserSIDs {
		aces = append(aces, fmt.Sprintf("(A;;GA;;;%s)", sid))
	}
	return "D:P" + strings.Join(aces, "")
}
