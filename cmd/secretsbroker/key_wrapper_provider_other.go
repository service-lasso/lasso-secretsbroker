//go:build !windows

package main

type unsupportedKeyWrapperProvider struct{}

func platformKeyWrapperProvider() keyWrapperProvider    { return unsupportedKeyWrapperProvider{} }
func (unsupportedKeyWrapperProvider) Algorithm() string { return "unsupported" }
func (unsupportedKeyWrapperProvider) Protect([]byte) ([]byte, error) {
	return nil, errUnsupportedOSWrapper
}
func (unsupportedKeyWrapperProvider) Unprotect([]byte) ([]byte, error) {
	return nil, errUnsupportedOSWrapper
}
func (unsupportedKeyWrapperProvider) SecurePath(string, bool) error   { return errUnsupportedOSWrapper }
func (unsupportedKeyWrapperProvider) ValidatePath(string, bool) error { return errUnsupportedOSWrapper }
