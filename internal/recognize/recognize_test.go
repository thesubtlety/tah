package recognize

import "testing"

func TestRecognizeCreds(t *testing.T) {
	// a real-shaped GitHub PAT is recognized (222 gitleaks rules, checksum-aware)
	got := Creds("github_pat = ghp_012345678901234567890123456789abcdef")
	if len(got) == 0 {
		t.Fatalf("expected a credential to be recognized")
	}
	found := false
	for _, c := range got {
		if c.Type == "github-pat" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected github-pat, got %+v", got)
	}
	// benign prose must not trip (entropy/allowlist filtering)
	if l := Creds("just some ordinary text, nothing secret in here at all"); len(l) != 0 {
		t.Errorf("false positive on benign text: %+v", l)
	}
}
