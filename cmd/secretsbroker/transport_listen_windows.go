//go:build windows

package main

import "net"

func listenForTransport(binding serveTransportBinding) (net.Listener, func(), error) {
	switch binding.Kind {
	case "loopback-http":
		ln, err := net.Listen(binding.Network, binding.Address)
		return ln, func() {}, err
	case "unix-socket":
		return nil, func() {}, errUnixSocketUnsupported()
	case "windows-named-pipe":
		return nil, func() {}, errWindowsNamedPipeRequiresIdentityChecks()
	default:
		return nil, func() {}, errUnsupportedTransport(binding.Kind)
	}
}
