package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

const auditChainGenesisHash = "genesis"

type auditChainVerification struct {
	Status     string `json:"status"`
	Verified   int    `json:"verified"`
	Failed     int    `json:"failed"`
	Unchecked  int    `json:"unchecked"`
	NextAction string `json:"nextAction,omitempty"`
}

func (b *localBackend) prepareChainedAuditEvent(event auditEvent) auditEvent {
	event.PreviousHash = firstNonEmpty(lastAuditEventHash(b.auditPath), auditChainGenesisHash)
	event.ChainStatus = "chained"
	event.EventHash = auditEventHash(event)
	return event
}

func lastAuditEventHash(path string) string {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return ""
	}
	defer file.Close()

	lastHash := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event auditEvent
		if json.Unmarshal([]byte(line), &event) == nil && strings.TrimSpace(event.EventHash) != "" {
			lastHash = strings.TrimSpace(event.EventHash)
		}
	}
	return lastHash
}

func auditEventHash(event auditEvent) string {
	event = normalizeAuditEvent(event)
	event.EventHash = ""
	event.ChainStatus = ""
	bytes, _ := json.Marshal(event)
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyAuditChain(events []auditEvent) (auditChainVerification, []auditEvent) {
	status := auditChainVerification{Status: "not_enabled"}
	lastHash := ""
	for i := range events {
		event := normalizeAuditEvent(events[i])
		if event.EventHash == "" {
			status.Unchecked++
			events[i] = event
			continue
		}
		expectedPrevious := firstNonEmpty(lastHash, auditChainGenesisHash)
		expectedHash := auditEventHash(event)
		if event.PreviousHash == expectedPrevious && event.EventHash == expectedHash {
			event.ChainStatus = "verified"
			status.Verified++
		} else {
			event.ChainStatus = "invalid"
			status.Failed++
		}
		lastHash = event.EventHash
		events[i] = event
	}
	switch {
	case status.Failed > 0:
		status.Status = "invalid"
		status.NextAction = "inspect_audit_chain"
	case status.Verified > 0 && status.Unchecked > 0:
		status.Status = "partial"
		status.NextAction = "keep_hash_chain_enabled_for_new_events"
	case status.Verified > 0:
		status.Status = "verified"
	default:
		status.Status = "not_enabled"
	}
	return status, events
}
