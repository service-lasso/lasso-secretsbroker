package main

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

// Preserve the original retention test. This supplemental observer makes each
// original write outcome visible instead of discarding the causal error.
func TestOperationalEventRetentionWriteOutcomes(t *testing.T) {
	backend := testBackend(t)
	ref := "services/api/runtime/API_TOKEN"
	if _, err := backend.writeSecret(writeSecretRequest{Ref: ref, Value: operationalEventSecretValue}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxOperationalEventLimit+5; i++ {
		backend.now = func() time.Time {
			return time.Date(2026, 5, 7, 0, 0, i, 0, time.UTC)
		}
		if err := backend.writeAuditEvent(auditEvent{
			TS: backend.now(), Operation: "policy_decision", ServiceID: fmt.Sprintf("api-%d", i),
			Ref: ref, Outcome: "denied", RequestID: fmt.Sprintf("req-%d", i),
		}); err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				t.Errorf("original write %d failed (%T, native errno %d): %+v", i, err, uint64(errno), err)
			} else {
				t.Errorf("original write %d failed (%T): %+v", i, err, err)
			}
		}
		audit, auditErr := readAuditEvents(backend.auditPath)
		events, eventErr := loadOperationalEvents(backend.eventPath)
		last := ""
		if len(events) > 0 {
			last = events[len(events)-1].RequestID
		}
		t.Logf("write=%d auditCount=%d auditReadError=%v eventCount=%d lastRequestID=%q eventReadError=%v", i, len(audit), auditErr, len(events), last, eventErr)
		if auditErr != nil || eventErr != nil {
			t.Errorf("write %d readback failed", i)
		}
	}
	res, err := buildEventsResponse(backend.eventPath, eventFilters{Limit: maxOperationalEventLimit})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != maxOperationalEventLimit {
		t.Fatalf("event count = %d, want %d", len(res.Events), maxOperationalEventLimit)
	}
	if res.Events[0].RequestID != "req-5" {
		t.Fatalf("retention first = %q, want req-5", res.Events[0].RequestID)
	}
}
