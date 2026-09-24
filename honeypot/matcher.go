// Package honeypot provides middleware for recognizing common vulnerability
// scanner probes and replying with a harmless ZIP decoy.
package honeypot

import (
	"path"
	"strings"
)

// Matcher reports whether a request path resembles a common secret, backup, or
// vulnerable-software probe. Matching is case-insensitive and operates on
// cleaned URL paths.
type Matcher struct{}

var exactProbePaths = map[string]struct{}{
	"/.git": {}, "/.git/config": {}, "/.git/head": {},
	"/.svn/entries": {}, "/.hg/store": {},
	"/.aws/credentials": {}, "/.aws/config": {},
	"/.ssh/id_rsa": {}, "/.ssh/authorized_keys": {},
	"/wp-login.php": {}, "/xmlrpc.php": {}, "/wp-config.php": {},
	"/phpinfo.php": {}, "/phpmyadmin": {}, "/pma": {},
	"/server-status": {}, "/server-info": {},
	"/actuator/env": {}, "/actuator/heapdump": {},
	"/debug/default/view": {}, "/console": {},
	"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php": {},
	"/cgi-bin": {},
}

var exactProbeSegments = map[string]struct{}{
	".env": {}, ".htaccess": {}, ".htpasswd": {}, ".ds_store": {},
	"wp-admin": {}, "phpmyadmin": {}, "pma": {},
}

// Match returns true for known scanner paths, including secret-file names at
// any depth and common exploit or backup suffixes.
func (Matcher) Match(requestPath string) bool {
	if requestPath == "" {
		return false
	}
	clean := path.Clean("/" + strings.TrimSpace(requestPath))
	lower := strings.ToLower(clean)
	if _, ok := exactProbePaths[lower]; ok {
		return true
	}
	for _, prefix := range []string{"/.git/", "/.svn/", "/.hg/", "/.aws/", "/.ssh/", "/wp-admin/", "/phpmyadmin/", "/pma/", "/cgi-bin/"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, segment := range strings.Split(strings.Trim(lower, "/"), "/") {
		if _, ok := exactProbeSegments[segment]; ok {
			return true
		}
		if strings.HasPrefix(segment, ".env.") || strings.HasPrefix(segment, ".env-") {
			return true
		}
	}
	base := path.Base(lower)
	for _, suffix := range []string{".sql", ".sql.gz", ".sql.zip", ".bak", ".backup", ".old", ".orig", ".swp", ".save", ".dump"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	for _, name := range []string{"config.php", "php.ini", "id_rsa", "credentials", "database.yml", "docker-compose.yml", "composer.lock"} {
		if base == name {
			return true
		}
	}
	return false
}
