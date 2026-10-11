package retention

import (
	"reflect"
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	now := time.Date(2026, 10, 11, 15, 0, 0, 0, time.UTC)
	got := Expired([]string{
		"signalith-authentication-2026.07.12",
		"signalith-authentication-2026.07.13",
		"signalith-other-2026.10.11",
		"signalith-notdated",
	}, 90, now)
	if !reflect.DeepEqual(got, []string{"signalith-authentication-2026.07.12"}) {
		t.Errorf("got %v", got)
	}
	if Expired([]string{"signalith-x-2000.01.01"}, 0, now) != nil {
		t.Error("0 days must keep everything")
	}
}
