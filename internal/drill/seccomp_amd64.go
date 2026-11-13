package drill

import "golang.org/x/sys/unix"

// seccompArch: the audit architecture and the calls only amd64 has.
func seccompArch() (uint32, []uintptr, error) {
	return unix.AUDIT_ARCH_X86_64, []uintptr{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_USELIB, unix.SYS__SYSCTL,
		unix.SYS_CREATE_MODULE, unix.SYS_GET_KERNEL_SYMS, unix.SYS_QUERY_MODULE}, nil
}
