// Program main is an HTML web server that renders a Google
// Authenticator enrollment QR code on a command line modifiable
// address.
//
// The purpose of this program is to demonstrate how to use the otp
// package. It is not recommended that you use this program without
// modification!
package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"zappem.net/pub/auth/otp"
)

var (
	secret = flag.String("secret", "", "force the base32 encoded key value")
	addr   = flag.String("addr", "localhost:8080", "address to listen to for web request")
	issuer = flag.String("issuer", "myOTP", "name of the key issuer")
	id     = flag.String("id", "nobody@localhost", "id of key owner")
)

var index = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Fake OTP server</title>
  </head>
  <body>
    <table>
      <tr>
        <td><img src="qr.png"/></td>
        <td>
          <ul>
            <li>Issuer: {{.Issuer}}</li>
            <li>ID: {{.ID}}</li>
            <li>[ Secret: {{.Secret}} ]</li>
            <li>Last: {{.Last}}</li>
            <li>This: {{.This}}</li>
            <li>Next: {{.Next}}</li>
          </ul>
        </td>
      </tr>
  </body>
</html>
`))

type Handle struct {
	ID, Issuer, Secret string
	Last, This, Next   string
	ki                 *otp.KnownIDs
	just               sync.Once
	img                []byte
}

func codeString(code int) string {
	x := fmt.Sprintf("%06d", code)
	return fmt.Sprint(x[:3], " ", x[3:])
}

func (h *Handle) dumpTemplate(w http.ResponseWriter) {
	now := time.Now().Unix() / 30
	last, _ := h.ki.Code(h.ID, now-1)
	h.Last = codeString(last)
	this, _ := h.ki.Code(h.ID, now)
	h.This = codeString(this)
	next, _ := h.ki.Code(h.ID, now+1)
	h.Next = codeString(next)
	index.Execute(w, h)
}

func (h *Handle) dumpQRCode(w http.ResponseWriter) {
	h.just.Do(func() {
		uri, err := h.ki.TimeURI(h.ID)
		if err != nil {
			log.Fatalf("failed to determine URI: %v", err)
		}
		h.img, err = qrcode.Encode(uri, qrcode.High, 256)
		if err != nil {
			log.Fatalf("failed to render QR code: %v", err)
		}
	})
	w.Header().Set("Content-Type", http.DetectContentType(h.img))
	w.Write(h.img)
}

func (h *Handle) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/qr.png":
		h.dumpQRCode(w)
	case "/", "/index.html":
		h.dumpTemplate(w)
	default:
		http.NotFound(w, r)
	}
}

func main() {
	flag.Parse()
	h := &Handle{
		ID:     *id,
		Issuer: *issuer,
		ki:     otp.NewKnownIDs(*issuer),
	}
	if *secret != "" {
		err := h.ki.AddKey(*id, *secret)
		if err != nil {
			log.Fatalf("failed to add %q for %q", *secret, *id)
		}
	} else {
		err := h.ki.GenKey(*id)
		if err != nil {
			log.Fatalf("failed to generate secret for %q", *id)
		}
	}
	h.Secret = h.ki.Map[*id]
	http.HandleFunc("/", h.handler)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
