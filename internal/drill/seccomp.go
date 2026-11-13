package drill

import (
	"golang.org/x/sys/unix"
)

// The sandbox's seccomp filter. It is a deny list on top of the
// capability drop (confine.go): Samba, Python and the C library need a
// broad set of system calls, so instead of an allow list that a Samba
// update could break, it refuses what a confined Samba never needs and
// what would help it leave the sandbox. A refused call fails with EPERM
// (clone3 with ENOSYS, so the C library falls back to clone, whose
// namespace flags the filter can see). A call from another architecture's
// ABI kills the process.

// deniedSyscalls fail with EPERM on every architecture.
var deniedSyscalls = []uintptr{
	// Mounts and the root: the sandbox's mounts are final.
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE,
	unix.SYS_OPEN_TREE_ATTR, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	// Namespaces (clone with namespace flags is handled separately).
	unix.SYS_UNSHARE, unix.SYS_SETNS,
	// Kernel code and state.
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_LOOKUP_DCOOKIE, unix.SYS_SYSLOG, unix.SYS_ACCT, unix.SYS_REBOOT,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_QUOTACTL, unix.SYS_QUOTACTL_FD, unix.SYS_NFSSERVCTL, unix.SYS_VHANGUP,
	// Other processes' memory and descriptors.
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_KCMP, unix.SYS_PIDFD_GETFD,
	// File handles: open_by_handle_at reaches files outside the root.
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
	// Keyrings are not confined by the namespaces (and may hold the host's
	// keys); Samba's Kerberos uses file and memory credential caches.
	unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL,
	// io_uring runs operations the filter cannot see; userfaultfd and
	// fanotify are common exploitation aids.
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_USERFAULTFD, unix.SYS_FANOTIFY_INIT,
	// Clock and identity of the host.
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX, unix.SYS_SETHOSTNAME,
	unix.SYS_SETDOMAINNAME,
}

// cloneNamespaceFlags are the CLONE_NEW* flags of clone(2)'s first
// argument (CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
// CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET).
const cloneNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// Offsets in struct seccomp_data.
const (
	offNr   = 0
	offArch = 4
	offArg0 = 16 // low 32 bits on little-endian amd64 and arm64
)

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// seccompProgram builds the filter for this architecture.
func seccompProgram() ([]unix.SockFilter, error) {
	arch, extra, err := seccompArch()
	if err != nil {
		return nil, err
	}
	const (
		ld   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	eperm := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	p := []unix.SockFilter{
		stmt(ld, offArch),
		jump(jeq, arch, 1, 0),
		stmt(ret, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(ld, offNr),
	}
	if arch == unix.AUDIT_ARCH_X86_64 {
		// The x32 ABI shares AUDIT_ARCH_X86_64 and sets bit 30 of the
		// number: refuse it whole.
		p = append(p, jump(jge, 0x40000000, 0, 1), stmt(ret, eperm))
	}
	for _, nr := range append(append([]uintptr(nil), deniedSyscalls...), extra...) {
		p = append(p, jump(jeq, uint32(nr), 0, 1), stmt(ret, eperm))
	}
	p = append(p,
		jump(jeq, uint32(unix.SYS_CLONE3), 0, 1), stmt(ret, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)),
		// clone: refuse namespace flags.
		jump(jeq, uint32(unix.SYS_CLONE), 0, 3),
		stmt(ld, offArg0),
		jump(jset, cloneNamespaceFlags, 0, 1),
		stmt(ret, eperm),
		stmt(ret, unix.SECCOMP_RET_ALLOW),
	)
	return p, nil
}
