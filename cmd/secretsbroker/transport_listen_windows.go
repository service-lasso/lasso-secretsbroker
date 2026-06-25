//go:build windows

package main

import (
	"net"

	winio "github.com/Microsoft/go-winio"
)

func listenForTransport(binding serveTransportBinding) (net.Listener, func(), error) {
	switch binding.Kind {
	case "loopback-http":
		ln, err := net.Listen(binding.Network, binding.Address)
		return ln, func() {}, err
	case "unix-socket":
		return nil, func() {}, errUnixSocketUnsupported()
	case "windows-named-pipe":
		userSID, err := currentWindowsUserSIDString()
		if err != nil {
			return nil, func() {}, err
		}
		ln, err := winio.ListenPipe(binding.Address, &winio.PipeConfig{
			SecurityDescriptor: windowsNamedPipeSecurityDescriptor(userSID),
			InputBufferSize:    65536,
			OutputBufferSize:   65536,
		})
		if err != nil {
			return nil, func() {}, err
		}
		authenticated := authenticatedWindowsNamedPipeListener(ln, userSID)
		return authenticated, func() { _ = authenticated.Close() }, nil
	default:
		return nil, func() {}, errUnsupportedTransport(binding.Kind)
	}
}
