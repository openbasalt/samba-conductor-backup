//go:build !amd64 && !arm64

package drill

import (
	"errors"
	"runtime"
)

// seccompArch: drills are supported on amd64 and arm64 only; elsewhere the
// sandbox refuses to start rather than run without its filter.
func seccompArch() (uint32, []uintptr, error) {
	return 0, nil, errors.New("the drill sandbox's seccomp filter is not defined for " + runtime.GOARCH)
}
