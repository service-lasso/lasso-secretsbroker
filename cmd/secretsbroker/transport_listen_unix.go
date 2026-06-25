//go:build !windows

package main

import (
	"net"
	"os"
)

func listenForTransport(binding serveTransportBinding) (net.Listener, func(), error) {
	switch binding.Kind {
	case "loopback-http":
		ln, err := net.Listen(binding.Network, binding.Address)
		return ln, func() {}, err
	case "unix-socket":
		_ = os.Remove(binding.Address)
		ln, err := net.Listen("unix", binding.Address)
		if err != nil {
			return nil, func() {}, err
		}
		rawLn := ln
		ln, err = authenticatedUnixSocketListener(rawLn)
		if err != nil {
			_ = rawLn.Close()
			_ = os.Remove(binding.Address)
			return nil, func() {}, err
		}
		_ = os.Chmod(binding.Address, 0o600)
		return ln, func() { _ = os.Remove(binding.Address) }, nil
	case "windows-named-pipe":
		return nil, func() {}, errWindowsNamedPipeUnsupported()
	default:
		return nil, func() {}, errUnsupportedTransport(binding.Kind)
	}
}
