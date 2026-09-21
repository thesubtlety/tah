package classify

import "testing"

// Pins the vendored catalog: representative macOS paths must classify to the
// expected class. Guards internal/classify/catalog.json against silent breakage.
func TestVendoredCatalogClassifies(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/Users/x/.ssh/id_rsa":                                                  "private_key",
		"/Users/x/.aws/credentials":                                             "cloud_auth",
		"/Users/x/Library/Keychains/login.keychain-db":                          "os_credential",
		"/Users/x/Library/Application Support/Google/Chrome/Default/Login Data": "browser_state",
		"/Users/x/vault.kdbx":                                                   "password_store",
		"/Users/x/.git-credentials":                                             "developer_secret",
	}
	for path, want := range cases {
		labels := c.Classify(path)
		if !hasClass(labels, want) {
			t.Errorf("%s: want class %q, got %v", path, want, labels)
		}
	}
	// a plainly non-sensitive path must yield nothing
	if l := c.Classify("/Users/x/Downloads/notes.txt"); len(l) != 0 {
		t.Errorf("expected no labels for a plain file, got %v", l)
	}
}

func hasClass(labels []Label, class string) bool {
	for _, l := range labels {
		if l.Class == class {
			return true
		}
	}
	return false
}
