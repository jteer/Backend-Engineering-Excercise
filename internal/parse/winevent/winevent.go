// Package winevent maps Windows Security EventIDs to normalized event fields
// based on SCHEMA.md. It is shared by the NDJSON parser and
// by the syslog/CEF parser, which sees the same IDs inside CEF headers, so both
// formats classify the same event the same way.
package winevent

import "log-exercise/internal/model"

// EventType maps an EventID to event.type.
func EventType(id int) model.EventType {
	switch id {
	case 4624, 4648: // logon
		return model.EventTypeStart
	case 4625: // failed logon attempt (still a "start" per the spec)
		return model.EventTypeStart
	case 4634, 4647: // logoff
		return model.EventTypeEnd
	case 4688: // process creation
		return model.EventTypeStart
	case 4689: // process termination
		return model.EventTypeEnd
	}
	// 4720–4767 (IAM events) and everything else are "info".
	return model.EventTypeInfo
}

// Category maps an EventID to event.category.
func Category(id int) model.EventCategory {
	switch id {
	case 4624, 4625, 4634, 4647, 4648:
		return model.CategoryAuthentication
	case 4688, 4689:
		return model.CategoryProcess
	}
	// 4720–4767 (IAM events) and everything else are "host".
	return model.CategoryHost
}
