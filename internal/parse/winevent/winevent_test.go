package winevent

import (
	"testing"

	"log-exercise/internal/model"
)

func TestMapping(t *testing.T) {
	tests := []struct {
		id  int
		typ model.EventType
		cat model.EventCategory
	}{
		{4624, model.EventTypeStart, model.CategoryAuthentication},
		{4625, model.EventTypeStart, model.CategoryAuthentication},
		{4648, model.EventTypeStart, model.CategoryAuthentication},
		{4634, model.EventTypeEnd, model.CategoryAuthentication},
		{4647, model.EventTypeEnd, model.CategoryAuthentication},
		{4688, model.EventTypeStart, model.CategoryProcess},
		{4689, model.EventTypeEnd, model.CategoryProcess},
		{4720, model.EventTypeInfo, model.CategoryHost}, // IAM range start
		{4750, model.EventTypeInfo, model.CategoryHost},
		{4767, model.EventTypeInfo, model.CategoryHost}, // IAM range end
		{4768, model.EventTypeInfo, model.CategoryHost}, // just outside: default
		{0, model.EventTypeInfo, model.CategoryHost},
		{-1, model.EventTypeInfo, model.CategoryHost},
	}
	for _, tt := range tests {
		if got := EventType(tt.id); got != tt.typ {
			t.Errorf("EventType(%d) = %s, want %s", tt.id, got, tt.typ)
		}
		if got := Category(tt.id); got != tt.cat {
			t.Errorf("Category(%d) = %s, want %s", tt.id, got, tt.cat)
		}
	}
}
