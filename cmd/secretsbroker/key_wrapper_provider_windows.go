//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsDPAPIAlgorithm = "windows-dpapi-current-user"

const windowsFileAllAccess = windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)

var windowsDPAPIEntropy = []byte("service-lasso:@secretsbroker:master-key-wrapper:v2")

var (
	getWindowsNamedSecurityInfo = windows.GetNamedSecurityInfo
	setWindowsNamedSecurityInfo = windows.SetNamedSecurityInfo
)

type windowsDPAPIKeyWrapperProvider struct{}

func platformKeyWrapperProvider() keyWrapperProvider     { return windowsDPAPIKeyWrapperProvider{} }
func (windowsDPAPIKeyWrapperProvider) Algorithm() string { return windowsDPAPIAlgorithm }

func (windowsDPAPIKeyWrapperProvider) Protect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errInvalidMasterKey
	}
	input := dataBlob(plaintext)
	entropy := dataBlob(windowsDPAPIEntropy)
	description, err := windows.UTF16PtrFromString("Service Lasso Secrets Broker portable master key")
	if err != nil {
		return nil, err
	}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, description, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(windowsDPAPIEntropy)
	return copyDataBlob(output)
}

func (windowsDPAPIKeyWrapperProvider) Unprotect(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errInvalidWrapper
	}
	input := dataBlob(ciphertext)
	entropy := dataBlob(windowsDPAPIEntropy)
	var output windows.DataBlob
	var description *uint16
	if err := windows.CryptUnprotectData(&input, &description, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	if description != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(description)))
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(windowsDPAPIEntropy)
	return copyDataBlob(output)
}

func dataBlob(bytes []byte) windows.DataBlob {
	if len(bytes) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(bytes)), Data: &bytes[0]}
}

func copyDataBlob(blob windows.DataBlob) ([]byte, error) {
	if blob.Size == 0 || blob.Data == nil {
		return nil, errWrapperUnavailable
	}
	return append([]byte(nil), unsafe.Slice(blob.Data, blob.Size)...), nil
}

func (windowsDPAPIKeyWrapperProvider) SecurePath(path string, directory bool) error {
	if err := rejectWindowsReparsePoint(path, directory); err != nil {
		return err
	}
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	sd, err := windowsPrivateSecurityDescriptor(userSID, directory)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := setWindowsNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return err
	}
	// Tighten the DACL first. Besides minimizing the failure state, this gives
	// the current user WRITE_OWNER before correcting an elevated/default group
	// owner on existing wrapper paths.
	if err := setWindowsNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		userSID,
		nil,
		nil,
		nil,
	); err != nil {
		return err
	}
	return windowsDPAPIKeyWrapperProvider{}.ValidatePath(path, directory)
}

func (windowsDPAPIKeyWrapperProvider) ValidatePath(path string, directory bool) error {
	if err := rejectWindowsReparsePoint(path, directory); err != nil {
		return err
	}
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	sd, err := getWindowsNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return validateWindowsPrivateSecurityDescriptor(sd, userSID, directory)
}

func windowsPrivateSecurityDescriptor(userSID *windows.SID, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	if userSID == nil {
		return nil, errWrapperUnavailable
	}
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return nil, err
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	aces := []string{fmt.Sprintf("(A;%s;FA;;;SY)", inheritance)}
	if !userSID.Equals(systemSID) {
		aces = append(aces, fmt.Sprintf("(A;%s;FA;;;%s)", inheritance, userSID.String()))
	}
	return windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P%s", userSID.String(), strings.Join(aces, "")))
}

func validateWindowsPrivateSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR, userSID *windows.SID, directory bool) error {
	if sd == nil || userSID == nil {
		return errWrapperAccess
	}
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errWrapperAccess
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (!owner.Equals(userSID) && !owner.Equals(systemSID)) {
		return errWrapperAccess
	}
	dacl, _, err := sd.DACL()
	expectedACECount := uint16(2)
	if userSID.Equals(systemSID) {
		expectedACECount = 1
	}
	if err != nil || dacl == nil || dacl.AceCount != expectedACECount {
		return errWrapperAccess
	}
	seen := map[string]bool{}
	expectedFlags := uint8(0)
	if directory {
		expectedFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errWrapperAccess
		}
		if ace.Mask != windowsFileAllAccess || ace.Header.AceFlags != expectedFlags || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return errWrapperAccess
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(userSID) && !sid.Equals(systemSID) {
			return errWrapperAccess
		}
		if seen[sid.String()] {
			return errWrapperAccess
		}
		seen[sid.String()] = true
	}
	if !seen[userSID.String()] || !seen[systemSID.String()] {
		return errWrapperAccess
	}
	return nil
}

func currentWindowsUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, errWrapperUnavailable
	}
	return user.User.Sid.Copy()
}

func rejectWindowsReparsePoint(path string, directory bool) error {
	if err := rejectWindowsReparseTraversal(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() != directory {
		return errWrapperAccess
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errWrapperAccess
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errWrapperAccess
	}
	return nil
}

func rejectWindowsReparseTraversal(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absolute)
	if volume == "" {
		return errWrapperAccess
	}
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(absolute, current)
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		currentPtr, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(currentPtr)
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errWrapperAccess
		}
	}
	return nil
}
