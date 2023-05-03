// Program codes generates a sequence of 20 OTP codes from a
// --secret. This code was written to investigate issue #1.
//
// The --then argument can be used to regenerate codes for some time
// period. In the case of issue #1, I had copied out of Google
// Authenticator a set of codes for this same secret at the times
// listed in that issue and they didn't all match.
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"zappem.net/pub/auth/otp"
)

var (
	secret = flag.String("secret", "", "secret in base64 encoding")
	then   = flag.String("then", "", "timestamp")
)

func main() {
	flag.Parse()
	if *secret == "" {
		log.Fatal("usage ./codes --secret=<secret>")
	}
	ki := otp.NewKnownIDs("myOTP")
	ki.AddKey("test", *secret)
	now := time.Now().Unix()
	if *then != "" {
		x, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", *then)
		if err != nil {
			log.Fatalf("failed to parse %q: %v", *then, err)
		}
		now = x.Unix()
	}
	now /= 30
	for i := int64(0); i < 16; i++ {
		t := (now + i) * 30
		c, _ := ki.Code("test", now+i)
		fmt.Printf("%v %12d %34b %06d\n", time.Unix(t, 0), t, t, c)
	}
}
