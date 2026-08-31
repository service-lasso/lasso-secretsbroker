package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type sourceConfigSecurity struct {
	Configured    bool   `json:"configured"`
	Checked       bool   `json:"checked"`
	Platform      string `json:"platform,omitempty"`
	PathHash      string `json:"pathHash,omitempty"`
	Mode          string `json:"mode,omitempty"`
	State         string `json:"state"`
	Outcome       string `json:"outcome"`
	NextAction    string `json:"nextAction,omitempty"`
	BroadReadable bool   `json:"broadReadable,omitempty"`
	BroadWritable bool   `json:"broadWritable,omitempty"`
}

func inspectSourceConfigSecurity(path string) sourceConfigSecurity {
	path = strings.TrimSpace(path)
	security := sourceConfigSecurity{
		Configured: true,
		Checked:    true,
		Platform:   runtime.GOOS,
		PathHash:   hashAuditRef(path),
		State:      "unknown",
		Outcome:    "degraded",
		NextAction: "inspect_source_config",
	}
	info, err := os.Stat(path) // #nosec G703 -- startup-owned config path is inspected only to report permission metadata.
	if errors.Is(err, os.ErrNotExist) {
		security.State = "missing"
		security.Outcome = "missing_ref"
		security.NextAction = "check_sources_path"
		return security
	}
	if err != nil {
		security.State = "unavailable"
		security.Outcome = "source_unavailable"
		security.NextAction = "check_sources_path_permissions"
		return security
	}
	mode := info.Mode().Perm()
	classified := classifySourceConfigMode(mode, runtime.GOOS)
	classified.Configured = true
	classified.Checked = true
	classified.Platform = runtime.GOOS
	classified.PathHash = security.PathHash
	return classified
}

func classifySourceConfigMode(mode os.FileMode, platform string) sourceConfigSecurity {
	security := sourceConfigSecurity{
		Mode:     fmt.Sprintf("0%03o", mode.Perm()),
		State:    "protected",
		Outcome:  "ready",
		Platform: platform,
	}
	if platform == "windows" {
		security.State = "permission_model_unverified"
		security.Outcome = "not_verified"
		security.NextAction = "review_os_acl"
		return security
	}
	security.BroadReadable = mode.Perm()&0o044 != 0
	security.BroadWritable = mode.Perm()&0o022 != 0
	if mode.Perm()&0o077 != 0 {
		security.State = "broad_access"
		security.Outcome = "degraded"
		security.NextAction = "restrict_source_config_permissions"
	}
	return security
}

func defaultSourceConfigSecurity() sourceConfigSecurity {
	return sourceConfigSecurity{Configured: false, Checked: false, Outcome: "not_configured", State: "not_configured"}
}

func normalizeSourceConfigSecurity(security sourceConfigSecurity) sourceConfigSecurity {
	if security.State == "" && security.Outcome == "" {
		return defaultSourceConfigSecurity()
	}
	if security.State == "" {
		security.State = security.Outcome
	}
	if security.Outcome == "" {
		security.Outcome = security.State
	}
	return security
}
