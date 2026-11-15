// Package web embeds youkai's single-page control plane.
//
// It is hand-written (no framework, no build step) so the whole platform stays
// one Go binary with no Node toolchain in the supply chain. The UI is a control
// surface only: it can approve one step, stop a run, and read evidence. There is
// no "run everything" button, and there never will be.
package web

import "embed"

// Files holds the SPA assets.
//
//go:embed index.html app.js wizard.js chat.js stream.js style.css
var Files embed.FS
