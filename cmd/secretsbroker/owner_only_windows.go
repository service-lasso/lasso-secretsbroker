//go:build windows

package main

func secureOwnerOnlyPath(path string, directory bool) error {
	provider := platformKeyWrapperProvider()
	if err := provider.SecurePath(path, directory); err != nil {
		return err
	}
	return provider.ValidatePath(path, directory)
}
