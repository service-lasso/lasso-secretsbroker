package main

import "fmt"

func errUnsupportedTransport(kind string) error {
	return fmt.Errorf("unsupported serve transport %q", kind)
}

func errUnixSocketUnsupported() error {
	return fmt.Errorf("unix-socket transport is only available on Unix-like platforms")
}

func errUnixSocketRequiresPeerCredentials() error {
	return fmt.Errorf("unix-socket transport requires OS peer credential checks before serving secret-bearing APIs")
}

func errWindowsNamedPipeUnsupported() error {
	return fmt.Errorf("windows-named-pipe transport is only available on Windows")
}

func errWindowsNamedPipeRequiresIdentityChecks() error {
	return fmt.Errorf("windows-named-pipe transport is configured but not yet enabled; listener must enforce local client identity checks before serving secret-bearing APIs")
}
