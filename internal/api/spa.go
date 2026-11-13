package api

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"strings"

	"youkai/web"
)

// spaHandler serves the single-page shell.
func (s *Server) spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := web.Files.ReadFile("index.html")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SPA shell missing")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// No inline script, no inline style, no external origins. The control
		// plane is a local document, not a web app with a network budget.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; "+
				"connect-src 'self'; img-src 'self' data:; font-src 'self'; "+
				"form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = io.Copy(w, bytes.NewReader(b))
	})
}

// assetsHandler serves the embedded JS/CSS.
func (s *Server) assetsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/assets/")
		// path.Clean + a basename check: the embed FS is flat, and this keeps a
		// traversal attempt from even reaching it.
		name = path.Base(path.Clean("/" + name))
		if name == "" || name == "." || name == "/" {
			http.NotFound(w, r)
			return
		}
		b, err := web.Files.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch path.Ext(name) {
		case ".js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
}
