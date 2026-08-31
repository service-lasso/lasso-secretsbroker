package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const auditChainGenesisHash = "genesis"

const maxAuditEventBytes = 1 << 20

var (
	errAuditChainInvalid = errors.New("audit hash chain is invalid")
	errAuditLockTimeout  = errors.New("timed out acquiring audit lock")
)

type auditChainVerification struct {
	Status     string `json:"status"`
	Verified   int    `json:"verified"`
	Failed     int    `json:"failed"`
	Unchecked  int    `json:"unchecked"`
	NextAction string `json:"nextAction,omitempty"`
}

func prepareChainedAuditEvent(event auditEvent, previousHash string) auditEvent {
	event.PreviousHash = firstNonEmpty(previousHash, auditChainGenesisHash)
	event.ChainStatus = "chained"
	event.EventHash = auditEventHash(event)
	return event
}

func readAuditEvents(path string) ([]auditEvent, error) {
	file, err := openValidatedRegularFile(path, 256<<20, true)
	if errors.Is(err, os.ErrNotExist) {
		return []auditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > 0 {
		if _, err := file.Seek(-1, io.SeekEnd); err != nil {
			return nil, err
		}
		last := []byte{0}
		if _, err := io.ReadFull(file, last); err != nil {
			return nil, err
		}
		if last[0] != '\n' {
			return nil, fmt.Errorf("%w: incomplete final record", errAuditChainInvalid)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}

	events := []auditEvent{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxAuditEventBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			return nil, fmt.Errorf("%w: empty record", errAuditChainInvalid)
		}
		var event auditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("%w: malformed record", errAuditChainInvalid)
		}
		events = append(events, normalizeAuditEvent(event))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: audit read failed", errAuditChainInvalid)
	}
	return events, nil
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
	chainStarted := false
	for i := range events {
		event := normalizeAuditEvent(events[i])
		if event.EventHash == "" {
			if chainStarted || event.PreviousHash != "" {
				event.ChainStatus = "invalid"
				status.Failed++
			} else {
				event.ChainStatus = "unchecked"
				status.Unchecked++
			}
			events[i] = event
			continue
		}
		chainStarted = true
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
		status.NextAction = "archive_legacy_prefix_and_keep_hash_chain_enabled"
	case status.Verified > 0:
		status.Status = "verified"
	default:
		status.Status = "not_enabled"
	}
	return status, events
}
