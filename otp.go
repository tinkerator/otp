// Package otp support generation of and validation of time synchronized
// one-time-pad codes. The conventions used by this package are the
// default ones used by the Google Authenticator application.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

// KnownIDs holds access key material for a set of known IDs.
type KnownIDs struct {
	// mu can be used to synchronize access to the fields below.
	mu sync.Mutex

	// Issuer holds the OTP issuer name string.
	Issuer string

	// Map holds OTP secret information indexed by user ID.
	Map map[string]string
}

// NewKnownIDs returns a structure holding an issuer's list of secrets
// indexed by IDs.
func NewKnownIDs(issuer string) *KnownIDs {
	return &KnownIDs{
		Issuer: issuer,
		Map:    make(map[string]string),
	}
}

// ErrInvalid indicates the id requested is unknown.
var ErrInvalid = errors.New("invalid structure")

// ErrUnknown indicates the id requested is unknown.
var ErrUnknown = errors.New("id unknown")

// AddKey adds a (replacement) issuer key for the specified id. The 80
// bits of key material must be provided in valid base32 encoding.
func (ki *KnownIDs) AddKey(id, key string) error {
	if _, err := base32.StdEncoding.DecodeString(key); err != nil {
		return err
	}
	if ki == nil {
		return ErrInvalid
	}
	ki.mu.Lock()
	defer ki.mu.Unlock()
	ki.Map[id] = key
	return nil
}

// GenKey generates a random (replacement) issuer key for the
// specified id.
func (ki *KnownIDs) GenKey(id string) error {
	r, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer r.Close()
	d := make([]byte, 10)
	if n, err := io.ReadFull(r, d[:]); err != nil {
		return err
	} else if n != len(d) {
		return err
	}
	return ki.AddKey(id, base32.StdEncoding.EncodeToString(d))
}

// TimeURI returns a universal resource identifier for TOTP setup.
// Converting the returned string into a QR code, for example, will
// allow Google Authenticator to import the TOTP keys.
func (ki *KnownIDs) TimeURI(id string) (string, error) {
	if ki == nil {
		return "", ErrInvalid
	}
	ki.mu.Lock()
	defer ki.mu.Unlock()
	key := ki.Map[id]
	if key == "" {
		return "", ErrUnknown
	}
	org := url.QueryEscape(ki.Issuer)
	uid := url.QueryEscape(id)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", org, uid, key, org), nil
}

// Code generates a one time pad code for a given integer offset.
func (ki *KnownIDs) Code(id string, offset int64) (int, error) {
	if ki == nil {
		return -1, ErrInvalid
	}
	ki.mu.Lock()
	defer ki.mu.Unlock()
	k := ki.Map[id]
	if k == "" {
		return -1, ErrUnknown
	}
	key, err := base32.StdEncoding.DecodeString(k)
	if err != nil {
		return -1, ErrUnknown
	}
	d := make([]byte, 8)
	binary.BigEndian.PutUint64(d, uint64(offset))
	h := hmac.New(sha1.New, key)
	h.Write(d)
	sum := h.Sum(nil)
	i := sum[19] & 15
	code := binary.BigEndian.Uint32(sum[i : i+4])
	return int(code % 1000000), nil
}

// validateOffset validates a OTP with some adjust margin of error.
func (ki *KnownIDs) validateTimeCode(id string, code int, now int64, adjust uint) bool {
	ki.mu.Lock()
	_, ok := ki.Map[id]
	ki.mu.Unlock()
	if !ok {
		return false
	}
	for i := int64(0); i <= int64(adjust); i++ {
		if ref, err := ki.Code(id, now+i); err != nil {
			return false
		} else if ref == code {
			return true
		}
		if i == 0 {
			continue
		}
		if ref, err := ki.Code(id, now-i); err != nil {
			return false
		} else if ref == code {
			return true
		}
	}
	return false
}

// ValidateTimeCode validates a numerical code as satisfying the TOTP
// criteria. If adjust is non-zero then that many time value indices
// adjacent to the current time are also checked and any of them are
// considered valid. No attempts are made to protect against a replay
// attack.
func (ki *KnownIDs) ValidateTimeCode(id string, code int, adjust uint) bool {
	if ki == nil {
		return false
	}
	now := time.Now().Unix() / 30
	return ki.validateTimeCode(id, code, now, adjust)
}
