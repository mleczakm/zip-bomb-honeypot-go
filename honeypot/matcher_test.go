package honeypot

import "testing"

func TestMatcher(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/.env", true},
		{"/.env.production", true},
		{"/config/.ENV.local", true},
		{"/.git/config", true},
		{"/.aws/credentials", true},
		{"/wp-admin/install.php", true},
		{"/phpMyAdmin/index.php", true},
		{"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", true},
		{"/backup/database.sql.gz", true},
		{"/app/config.php.bak", true},
		{"/actuator/env", true},
		{"/ordinary/path", false},
		{"/login", false},
		{"/api/v1/users", false},
		{"/.envoy", false},
		{"", false},
	}
	matcher := Matcher{}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := matcher.Match(tt.path); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestMatcherCleansPath(t *testing.T) {
	for _, candidate := range []string{"/a/../.env", " /nested//wp-admin/ "} {
		if !(Matcher{}).Match(candidate) {
			t.Errorf("Match(%q) = false, want true", candidate)
		}
	}
}
