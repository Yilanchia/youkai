package web

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"mime/multipart"
	"text/template"
)

// randomToken is the marker a probe plants so it can recognise its own work.
func randomToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// A fixed fallback is still unambiguous: the token only has to be unique
		// within one probe, and a failing RNG has bigger problems than this.
		return "youkai-0000000000000000"
	}
	return hex.EncodeToString(buf)
}

// multipartFile builds a one-field upload body. The content is a plain-text marker:
// the probe is asking "will you take this?', not "will you run this?".
func multipartFile(field, filename, content string) ([]byte, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err == nil {
		_, _ = fw.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes(), w.FormDataContentType()
}

var _ = template.Must // keep the import list honest if this file grows
