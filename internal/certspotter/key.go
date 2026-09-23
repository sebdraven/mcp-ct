package certspotter

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// KeychainService is where the token is looked for on macOS.
const KeychainService = "api.certspotter.com"

// Token finds the Cert Spotter API key: the environment first, then the macOS
// keychain so it need not sit in cleartext in a client's config file.
//
// An empty result is not an error. The API answers unauthenticated requests at
// a much lower rate, and a domain that exhausts it falls through to crt.sh.
// The key is issued from the API Credentials page of an SSLMate account.
func Token() string {
	if t := strings.TrimSpace(os.Getenv("CERTSPOTTER_TOKEN")); t != "" {
		return t
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", "find-generic-password",
			"-s", KeychainService, "-w").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}
