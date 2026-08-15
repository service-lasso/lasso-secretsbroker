package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxStoreKeyMetadataSize = 64 << 20

type keyWrapperProvider interface {
	Algorithm() string
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
	SecurePath(path string, directory bool) error
	ValidatePath(path string, directory bool) error
}

func writePrivateWrapperAtomically(path string, bytes []byte, provider keyWrapperProvider) error {
	directory := filepath.Dir(path)
	if directory == "." || directory == string(filepath.Separator) || directory == filepath.VolumeName(directory)+string(filepath.Separator) {
		return errWrapperAccess
	}
	if err := cleanupPrivateWrapperTemps(path, provider); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := provider.SecurePath(tempPath, false); err != nil {
		return errWrapperAccess
	}
	if _, err := temp.Write(bytes); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := atomicReplacePrivateFile(tempPath, path); err != nil {
		return err
	}
	committed = true
	if err := provider.SecurePath(path, false); err != nil {
		return errWrapperAccess
	}
	if err := provider.ValidatePath(directory, true); err != nil {
		return errWrapperAccess
	}
	if err := provider.ValidatePath(path, false); err != nil {
		return errWrapperAccess
	}
	return nil
}

func cleanupPrivateWrapperTemps(path string, provider keyWrapperProvider) error {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		return err
	}
	for _, match := range matches {
		if err := provider.SecurePath(match, false); err != nil {
			return errWrapperAccess
		}
		if err := os.Remove(match); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func loadKeyMaterialWithWrapper(flagValue, filePath, wrapperPath string) (keyMaterial, error) {
	return loadKeyMaterialWithWrapperWithProvider(flagValue, filePath, wrapperPath, platformKeyWrapperProvider())
}

func loadKeyMaterialWithWrapperWithProvider(flagValue, filePath, wrapperPath string, provider keyWrapperProvider) (keyMaterial, error) {
	material, err := loadKeyMaterial(flagValue, filePath)
	if err == nil || !errors.Is(err, errLocked) || wrapperPath == "" {
		return material, err
	}
	if _, statErr := os.Stat(wrapperPath); errors.Is(statErr, os.ErrNotExist) {
		return material, errLocked
	} else if statErr != nil {
		return keyMaterial{Source: "os-wrapper"}, statErr
	}
	plaintext, unwrapErr := unwrapMasterKeyWithProvider(wrapperPath, wrapperContextFor(""), provider)
	if unwrapErr != nil {
		if errors.Is(unwrapErr, os.ErrNotExist) {
			return material, errLocked
		}
		return keyMaterial{Source: "os-wrapper"}, unwrapErr
	}
	defer zeroBytes(plaintext)
	return keyMaterial{Value: string(plaintext), Source: "os-wrapper"}, nil
}

func rotationPendingWrapperPath(wrapperPath string) string {
	return wrapperPath + ".rotation-pending"
}

// loadKeyMaterialForStore also completes or discards an interrupted managed
// rotation. The pending wrapper contains only OS-protected key bytes. It is
// promoted only when its key ID agrees with the atomically published store.
func loadKeyMaterialForStore(flagValue, filePath, wrapperPath, storePath string) (keyMaterial, error) {
	return loadKeyMaterialForStoreWithProvider(flagValue, filePath, wrapperPath, storePath, platformKeyWrapperProvider())
}

func loadKeyMaterialForStoreWithProvider(flagValue, filePath, wrapperPath, storePath string, provider keyWrapperProvider) (keyMaterial, error) {
	material, materialErr := loadKeyMaterialWithWrapperWithProvider(flagValue, filePath, wrapperPath, provider)
	storeKeyID, storeErr := readStoreKeyID(storePath)
	if errors.Is(storeErr, os.ErrNotExist) {
		return material, materialErr
	}
	if storeErr != nil {
		return keyMaterial{}, storeErr
	}
	if storeKeyID == "" {
		return material, materialErr
	}
	pendingPath := rotationPendingWrapperPath(wrapperPath)
	if materialErr == nil && masterKeyID(material.Value) == storeKeyID {
		if _, err := os.Lstat(pendingPath); err == nil {
			if err := provider.ValidatePath(pendingPath, false); err != nil {
				return keyMaterial{}, errWrapperAccess
			}
			if err := os.Remove(pendingPath); err != nil {
				return keyMaterial{}, err
			}
		}
		return material, nil
	}
	if strings.TrimSpace(wrapperPath) == "" {
		if materialErr != nil {
			return material, materialErr
		}
		return keyMaterial{}, errInvalidWrapper
	}
	pending, err := unwrapMasterKeyWithProvider(pendingPath, wrapperContextFor(""), provider)
	if err != nil {
		if materialErr != nil {
			return material, materialErr
		}
		return keyMaterial{}, errInvalidWrapper
	}
	defer zeroBytes(pending)
	if masterKeyID(string(pending)) != storeKeyID {
		return keyMaterial{}, errInvalidWrapper
	}
	if err := atomicReplacePrivateFile(pendingPath, wrapperPath); err != nil {
		return keyMaterial{}, err
	}
	if err := provider.SecurePath(wrapperPath, false); err != nil {
		return keyMaterial{}, errWrapperAccess
	}
	if err := provider.ValidatePath(wrapperPath, false); err != nil {
		return keyMaterial{}, errWrapperAccess
	}
	return keyMaterial{Value: string(pending), Source: "os-wrapper-rotation-recovery"}, nil
}

func (b *localBackend) lifecycleWrapperProvider() keyWrapperProvider {
	if b.wrapperProvider != nil {
		return b.wrapperProvider
	}
	return platformKeyWrapperProvider()
}

func readStoreKeyID(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxStoreKeyMetadataSize {
		return "", errInvalidWrapper
	}
	bytes, err := io.ReadAll(io.LimitReader(file, maxStoreKeyMetadataSize+1))
	if err != nil || int64(len(bytes)) > maxStoreKeyMetadataSize {
		return "", errInvalidWrapper
	}
	var metadata struct {
		KeyID string `json:"keyId"`
	}
	if json.Unmarshal(bytes, &metadata) != nil {
		return "", errInvalidWrapper
	}
	return strings.TrimSpace(metadata.KeyID), nil
}
