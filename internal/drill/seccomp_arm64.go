package drill

import "golang.org/x/sys/unix"

// seccompArch: the audit architecture (no calls specific to arm64).
func seccompArch() (uint32, []uintptr, error) {
	return unix.AUDIT_ARCH_AARCH64, nil, nil
}
