package honeypot

import "testing"

func FuzzMatcher(f *testing.F) {
	for _, seed := range []string{"/.env", "/wp-admin/", "/ordinary", "", "/a/../.git/config", "/💣"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, candidate string) {
		_ = (Matcher{}).Match(candidate)
	})
}

func BenchmarkMatcher(b *testing.B) {
	matcher := Matcher{}
	for i := 0; i < b.N; i++ {
		matcher.Match("/.env.production")
	}
}
