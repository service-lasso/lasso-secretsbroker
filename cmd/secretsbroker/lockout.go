package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	localAPILockoutThreshold = 3
	localAPILockoutCooldown  = 5 * time.Minute
)

type lockoutStore struct {
	mu        sync.Mutex
	entries   map[string]lockoutEntry
	now       func() time.Time
	threshold int
	cooldown  time.Duration
}

type lockoutEntry struct {
	Failures    int
	ActiveUntil time.Time
	LastFailure time.Time
}

type lockoutDecision struct {
	Active            bool
	Scope             string
	RetryAfterSeconds int
}

func newLockoutStore(now func() time.Time) *lockoutStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &lockoutStore{
		entries:   map[string]lockoutEntry{},
		now:       now,
		threshold: localAPILockoutThreshold,
		cooldown:  localAPILockoutCooldown,
	}
}

func localAPILockoutScope(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if host == "" {
		host = "local"
	}
	return "local_api:" + host
}

func (s *lockoutStore) active(scope string) lockoutDecision {
	if s == nil {
		return lockoutDecision{Scope: scope}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked(scope, s.now())
}

func (s *lockoutStore) recordFailure(scope string) (lockoutDecision, bool) {
	if s == nil {
		return lockoutDecision{Scope: scope}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if decision := s.activeLocked(scope, now); decision.Active {
		return decision, false
	}

	entry := s.entries[scope]
	if !entry.ActiveUntil.IsZero() && !entry.ActiveUntil.After(now) {
		entry = lockoutEntry{}
	}
	entry.Failures++
	entry.LastFailure = now
	started := false
	if entry.Failures >= s.threshold {
		entry.Failures = s.threshold
		entry.ActiveUntil = now.Add(s.cooldown)
		started = true
	}
	s.entries[scope] = entry
	return s.decision(scope, entry, now), started
}

func (s *lockoutStore) recordSuccess(scope string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, scope)
}

func (s *lockoutStore) activeLocked(scope string, now time.Time) lockoutDecision {
	entry, ok := s.entries[scope]
	if !ok {
		return lockoutDecision{Scope: scope}
	}
	if entry.ActiveUntil.After(now) {
		return s.decision(scope, entry, now)
	}
	if !entry.ActiveUntil.IsZero() {
		delete(s.entries, scope)
	}
	return lockoutDecision{Scope: scope}
}

func (s *lockoutStore) decision(scope string, entry lockoutEntry, now time.Time) lockoutDecision {
	decision := lockoutDecision{Scope: scope}
	if entry.ActiveUntil.After(now) {
		decision.Active = true
		decision.RetryAfterSeconds = int(time.Until(entry.ActiveUntil).Seconds())
		if s.now != nil {
			decision.RetryAfterSeconds = int(entry.ActiveUntil.Sub(now).Seconds())
		}
		if decision.RetryAfterSeconds < 1 {
			decision.RetryAfterSeconds = 1
		}
	}
	return decision
}
