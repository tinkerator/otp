package otp

import (
	"testing"
	"time"
)

func TestAddValidate(t *testing.T) {
	now, err := time.Parse(time.RFC3339, "2023-04-03T20:14:41-07:00")
	if err != nil {
		t.Fatalf("unable to parse time: %v", err)
	}

	ki := NewKnownIDs("acme")
	ki.AddKey("robby", "HEEKUKXMSYMV2B26")

	u, err := ki.TimeURI("robby")
	if err != nil {
		t.Fatalf("unable to generate TimeURI(\"robby\"): %v", err)
	}
	if want := "otpauth://totp/acme:robby?secret=HEEKUKXMSYMV2B26&issuer=acme"; want != u {
		t.Errorf("failed to get a URI: got=%q want=%q", u, want)
	}

	when := now.Unix() / 30
	got, err := ki.Code("robby", when)
	if err != nil {
		t.Fatalf("attempt to generate key failed: %v", err)
	}
	if want := 133968; got != want {
		t.Errorf("otp.Code got=%d want=%d", got, want)
	}

	then := when - 1
	got, err = ki.Code("robby", then)
	if ok := ki.validateTimeCode("robby", got, then, 0); !ok {
		t.Errorf("time code should be valid: when=%d vs %d", then, then)
	}
	if ok := ki.validateTimeCode("robby", got, when, 0); ok {
		t.Errorf("time code should not be valid: when=%d vs %d", when, then)
	}
	if ok := ki.validateTimeCode("robby", got, when, 1); !ok {
		t.Errorf("time code should be valid: when=%d vs %d (adjust=1)", when, then)
	}
}
