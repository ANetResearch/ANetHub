package admin

import "testing"

// The three console views answer behind the token, in the shape the page reads.
func TestOpsViewsAnswerBehindTheToken(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	for _, p := range []string{"/admin/api/admission", "/admin/api/delivery", "/admin/api/federation"} {
		if w, _ := doReq(t, h, "GET", p, "", nil); w.Code != 401 {
			t.Errorf("%s without a token: %d, want 401", p, w.Code)
		}
	}
	w, out := doReq(t, h, "GET", "/admin/api/admission", "test-token", nil)
	if w.Code != 200 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	if out["mode"] != "closed" && out["mode"] != "open" {
		t.Errorf("admission mode %v", out["mode"])
	}
	rules, _ := out["rules"].(map[string]any)
	if rules["probation_hours"] != float64(72) || rules["trial_credits"] != float64(20) {
		t.Errorf("rules %v", rules)
	}
	w, out = doReq(t, h, "GET", "/admin/api/delivery", "test-token", nil)
	if w.Code != 200 || out["confirmation_ttl_hours"] != float64(168) {
		t.Errorf("delivery: %d %v", w.Code, out)
	}
	if w, _ = doReq(t, h, "GET", "/admin/api/federation", "test-token", nil); w.Code != 200 {
		t.Errorf("federation: %d %s", w.Code, w.Body.String())
	}
}
