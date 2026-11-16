package drill

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/sambaconf"
	"golang.org/x/sys/unix"
)

// TestCheckIDMap: stage 2 runs only in the drill's mapping, never in the
// initial user namespace or one that maps host root.
func TestCheckIDMap(t *testing.T) {
	const base = config.DefaultUserNSBase
	good := fmt.Sprintf("         0 %d    %d\n", base, config.UserNSSize)
	m, err := parseIDMap([]byte(good))
	if err != nil || checkIDMap(m, base, config.UserNSSize) != nil {
		t.Fatalf("drill mapping refused: %v %v", m, err)
	}
	for name, text := range map[string]string{
		"initial namespace": "         0          0 4294967295\n",
		"host root mapped":  "         0          0      65536\n",
		"other base":        fmt.Sprintf("0 %d %d\n", base+65536, config.UserNSSize),
		"smaller range":     fmt.Sprintf("0 %d 65536\n", base),
		"two ranges":        good + "100000 0 1\n",
		"empty":             "",
	} {
		m, err := parseIDMap([]byte(text))
		if err != nil {
			continue
		}
		if checkIDMap(m, base, config.UserNSSize) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := parseIDMap([]byte("0 x 1\n")); err == nil {
		t.Error("garbage parsed")
	}
	if checkIDMap([]idRange{{0, 0, config.UserNSSize}}, 0, config.UserNSSize) == nil {
		t.Error("base 0 accepted")
	}
	// This test process runs in the initial user namespace (or the
	// runner's), never in the drill's mapping.
	if err := verifyUserNS(base); err == nil {
		t.Error("the test process passes as the drill's user namespace")
	}
}

func TestInnerSysProcAttr(t *testing.T) {
	a := innerSysProcAttr(config.DefaultUserNSBase)
	if a.Cloneflags != syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS || !a.GidMappingsEnableSetgroups || a.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("%+v", a)
	}
	want := syscall.SysProcIDMap{ContainerID: 0, HostID: config.DefaultUserNSBase, Size: config.UserNSSize}
	if len(a.UidMappings) != 1 || a.UidMappings[0] != want || len(a.GidMappings) != 1 || a.GidMappings[0] != want {
		t.Fatalf("maps %+v %+v", a.UidMappings, a.GidMappings)
	}
}

// TestUserNSUnavailable: only "the host does not allow it" errors may be
// downgraded by the opt-out; the message names both ways out.
func TestUserNSUnavailable(t *testing.T) {
	for _, e := range []error{unix.EPERM, unix.ENOSPC, unix.EINVAL, unix.EUSERS, unix.ENOSYS, &os.SyscallError{Syscall: "clone", Err: unix.EPERM}} {
		if !userNSUnavailable(e) {
			t.Errorf("%v not classified", e)
		}
	}
	for _, e := range []error{unix.ENOENT, unix.ENOMEM, errors.New("x")} {
		if userNSUnavailable(e) {
			t.Errorf("%v classified as unavailable", e)
		}
	}
	msg := noUserNSError(unix.EPERM).Error()
	if !errors.Is(noUserNSError(unix.EPERM), errNoUserNS) || !strings.Contains(msg, "accept_no_userns") || !strings.Contains(msg, "--accept-no-userns") {
		t.Fatalf("message %q", msg)
	}
}

// TestChownTree walks without following links (own IDs: no privilege
// needed).
func TestChownTree(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "x", "y"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "x", "y", "f"), []byte("x"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := chownTree(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := chownTree(dir, config.DefaultUserNSBase, config.DefaultUserNSBase); err == nil {
			t.Fatal("chown to another user succeeded without privilege")
		}
	}
}

func TestScriptInterpreter(t *testing.T) {
	dir := t.TempDir()
	for text, want := range map[string]string{
		"#!/usr/bin/python3\nimport x\n":    "/usr/bin/python3",
		"#! /usr/bin/python3 -s\n":          "/usr/bin/python3",
		"#!/usr/bin/env sh\n":               "/usr/bin/sh",
		"#!python3\n":                       "",
		"import x\n":                        "",
		"#!/usr/bin/env ../../tmp/python\n": "",
	} {
		p := filepath.Join(dir, "samba-tool")
		_ = os.WriteFile(p, []byte(text), 0o755)
		got, err := scriptInterpreter(p)
		if want == "" {
			if err == nil {
				t.Errorf("%q: accepted as %q", text, got)
			}
			continue
		}
		if want == "/usr/bin/sh" {
			// env: the first match in the sandbox's PATH.
			if err != nil || filepath.Base(got) != "sh" {
				t.Errorf("%q: %q %v", text, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: %q %v", text, got, err)
		}
	}
}

func TestCheckKDC(t *testing.T) {
	if checkKDC(sambaconf.KDCMIT, sambaconf.KDCMIT) != nil || checkKDC(sambaconf.KDCHeimdal, sambaconf.KDCHeimdal) != nil {
		t.Fatal("same flavour refused")
	}
	err := checkKDC(sambaconf.KDCHeimdal, sambaconf.KDCMIT)
	if !errors.Is(err, errKDCMismatch) || !strings.Contains(err.Error(), "Heimdal KDC and this drill host's Samba uses the MIT Kerberos KDC") {
		t.Fatalf("%v", err)
	}
}
