package admin

import _ "embed"

//go:embed web/admin.html
var adminHTML []byte

// AdminHTML returns the embedded single-file operator SPA (same embed pattern as the public hub's
// aghub.IndexHTML — hand-authored, no build step, no CDN).
func AdminHTML() []byte { return adminHTML }
