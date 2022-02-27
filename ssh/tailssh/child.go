// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package tailssh

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/types/logger"
)

func init() {
	childproc.Add("ssh", sshChild)
}

var ptyName = func(f *os.File) (string, error) {
	return "", fmt.Errorf("unimplemented")
}

var startLoginSession = func(logf logger.Logf, uid uint32, localUser, remoteUser, remoteHost, tty string) (close func() error, err error) {
	return nil, fmt.Errorf("unimplemented")
}

// newSSHChildCommand returns a new exec.Cmd configured with
// `tailscaled be-child ssh` as the entrypoint.
// If tailscaled is empty, the subcommand is not configured.
func newSSHChildCommand(ctx context.Context, uid string, ci *sshConnInfo, tailscaled, name string, args []string) *exec.Cmd {
	if tailscaled != "" {
		args = append([]string{"be-child", "ssh", name}, args...)
		name = tailscaled
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if tailscaled != "" {
		// Don't bother setting these if we aren't spawning tailscaled.
		cmd.Env = []string{
			"TS_UID=" + uid,
			"TS_LOCAL_USER=" + ci.localUser,
			"TS_REMOTE_USER=" + ci.uprof.LoginName,
			"TS_REMOTE_TAGS=" + strings.Join(ci.node.Tags, ","),
			"TS_REMOTE_IP=" + ci.src.IP().String(),
		}
	}
	return cmd
}

const debugChild = false

// sshChild is the entrypoint to the `tailscaled be-child ssh` subcommand.
// This adds a necessary layer of indirection between tailscaled and the
// process that we are about to spawn. One of the primary requirements
// is to inform the system of new login session from the user. This is
// typically necessary for mounting home directories and decrypting file
// systems.
// It expects the following env variables:
// - TS_UID
// - TS_LOCAL_USER
// - TS_REMOTE_USER
// - TS_REMOTE_TAGS
// - TS_REMOTE_IP
// - TS_HAS_TTY
// - TS_TTY_NAME
func sshChild(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no args provided")
	}
	logf := logger.Discard
	if debugChild {
		// The only place we can log is syslog.
		if sl, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "tailscaled-ssh"); err == nil {
			logf = log.New(sl, "", 0).Printf
		}
	}
	localUser := os.Getenv("TS_LOCAL_USER")

	uid, err := strconv.ParseUint(os.Getenv("TS_UID"), 10, 32)
	if err != nil {
		logf("ssh: user Lookup %q: %v", localUser, err)
		os.Exit(1)
	}

	euid := uint64(os.Geteuid())
	if euid == 0 {
		// Inform the system that we are about to login someone.
		// We can only do this if we are running as root.
		remoteUser := os.Getenv("TS_REMOTE_TAGS")
		if remoteUser == "" {
			remoteUser = os.Getenv("TS_REMOTE_USER")
		}
		closer, err := startLoginSession(logf, uint32(uid), localUser, remoteUser, os.Getenv("TS_REMOTE_IP"), os.Getenv("TS_TTY_NAME"))
		if err == nil && closer != nil {
			defer closer()
		}
	}
	if euid != uid {
		// Switch users if required before starting the desired process.
		if err := syscall.Setuid(int(uid)); err != nil {
			logf(err.Error())
			os.Exit(1)
		}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	env := os.Environ()
	cmd.Stderr = os.Stderr
	cmd.Env = env[:0]
	// Filter out `TS_` env variables to prevent Hyrum's law.
	// TODO(maisem): should we let these through, or add any more?
	// TODO(maisem): maybe only filter out the env variables that we own?
	for _, e := range env {
		if !strings.HasPrefix(e, "TS_") {
			cmd.Env = append(cmd.Env, e)
		}
	}

	if os.Getenv("TS_HAS_TTY") != "" {
		// If we were launched with a tty then we should
		// mark that as the ctty of the child. However,
		// as the ctty is being passed from the parent
		// we set the child to foreground instead which
		// also passes the ctty.
		// However, we can not do this if never had a tty to
		// begin with.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Foreground: true,
		}
	}
	return cmd.Run()
}

func openPTY(cmd *exec.Cmd, ptyReq ssh.Pty) (ptyFile *os.File, tty *os.File, err error) {
	ptyFile, tty, err = pty.Open()
	if err != nil {
		err = fmt.Errorf("pty.Open: %w", err)
		return
	}

	defer func() {
		if err != nil {
			ptyFile.Close()
			tty.Close()
		}
	}()
	if err = pty.Setsize(ptyFile, &pty.Winsize{
		Rows: uint16(ptyReq.Window.Width),
		Cols: uint16(ptyReq.Window.Height),
	}); err != nil {
		err = fmt.Errorf("pty.Setsize: %w", err)
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}

	if ptyPath, err := ptyName(ptyFile); err == nil {
		cmd.Env = append(cmd.Env, "TS_TTY_NAME="+ptyPath)
	}

	return ptyFile, tty, nil
}

func startChild(s ssh.Session, cmd *exec.Cmd) (stdin io.WriteCloser, stdout, stderr io.Reader, err error) {
	ptyReq, winCh, isPty := s.Pty()

	if !isPty {
		return startWithStdPipes(cmd)
	}
	pty, tty, err := openPTY(cmd, ptyReq)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil {
			pty.Close()
			tty.Close()
		}
	}()
	cmd.Env = append(cmd.Env, "TS_HAS_TTY=1")
	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	go func() {
		for win := range winCh {
			setWinsize(pty, win.Width, win.Height)
		}
	}()
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	// When using a pty we don't get a separate reader for stderr.
	return pty, pty, nil, nil
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func startWithStdPipes(cmd *exec.Cmd) (stdin io.WriteCloser, stdout, stderr io.ReadCloser, err error) {
	defer func() {
		if err != nil {
			for _, c := range []io.Closer{stdin, stdout, stderr} {
				if c != nil {
					c.Close()
				}
			}
		}
	}()
	stdin, err = cmd.StdinPipe()
	if err != nil {
		return
	}
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return
	}
	err = cmd.Start()
	return
}
