package syslog

import (
	"strings"

	"log-exercise/internal/model"
	"log-exercise/internal/parse/winevent"
)

// Keyword rules for syslog/CEF events
var (
	authWords    = []string{"auth", "logon", "login", "log on", "logged on", "logoff", "log off", "logged off", "logout", "log out"}
	endWords     = []string{"logoff", "log off", "logged off", "logout", "log out", "logged out"}
	networkWords = []string{"traffic", "connection"}

	// Failure is checked before success so that "unsuccessful" and mixed messages are never reported as success.
	failureWords = []string{"failure", "failed", "unsuccessful", "deny", "denied", "blocked", "rejected", "dropped"}
	successWords = []string{"success", "succeeded", "allow", "permitted", "accepted"}

	allowActs = map[string]bool{"allow": true, "allowed": true, "permit": true, "permitted": true, "accept": true, "accepted": true, "pass": true}
	denyActs  = map[string]bool{"deny": true, "denied": true, "block": true, "blocked": true, "drop": true, "dropped": true, "reject": true, "rejected": true, "discard": true}
)

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// facts are the already-lower-cased inputs the classifier looks at.
type facts struct {
	winID      int // Windows EventID
	class      string
	name       string
	msg        string
	act        string
	outcomeExt string
}

func (f facts) text() string { return f.class + " " + f.name + " " + f.msg }

func categoryOf(f facts) model.EventCategory {
	if f.winID > 0 {
		if c := winevent.Category(f.winID); c != model.CategoryHost {
			return c
		}
	}
	text := f.text()
	switch {
	case containsAny(text, authWords):
		return model.CategoryAuthentication
	case containsAny(text, networkWords):
		return model.CategoryNetwork
	}
	return model.CategoryHost
}

// typeOf follows the spec's order: CEF act first, then auth context, else info.
func typeOf(f facts, cat model.EventCategory) model.EventType {
	act := strings.TrimSpace(f.act)
	switch {
	case allowActs[act]:
		return model.EventTypeAllowed
	case denyActs[act]:
		return model.EventTypeDenied
	}
	// A known Windows event id uses the same table as the JSON path, so the
	// two formats agree on start/end for process and logon events.
	if f.winID > 0 {
		return winevent.EventType(f.winID)
	}
	if cat == model.CategoryAuthentication {
		if containsAny(f.text(), endWords) {
			return model.EventTypeEnd
		}
		return model.EventTypeStart
	}
	return model.EventTypeInfo
}

func outcomeOf(f facts) model.EventOutcome {
	// An explicit outcome= extension is the sender's own statement; trust it.
	switch strings.TrimSpace(f.outcomeExt) {
	case "success", "succeeded", "successful", "ok":
		return model.OutcomeSuccess
	case "failure", "failed", "fail", "error":
		return model.OutcomeFailure
	}
	text := f.act + " " + f.text()
	switch {
	case containsAny(text, failureWords):
		return model.OutcomeFailure
	case containsAny(text, successWords):
		return model.OutcomeSuccess
	}
	return model.OutcomeUnknown
}

// syslogLevel maps the RFC 3164 severity (PRI & 7) to a log.level string.
func syslogLevel(pri int) string {
	return [...]string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}[pri&7]
}
