// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package tailssh

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/godbus/dbus/v5"
	"tailscale.com/types/logger"
)

func init() {
	ptyName = ptyNameLinux
	startLoginSession = startLoginSessionLinux
}

func ptyNameLinux(f *os.File) (string, error) {
	var n uint32
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if e != 0 {
		return "", e
	}
	return fmt.Sprintf("pts/%d", n), nil
}

func callLogin1(method string, flags dbus.Flags, args ...interface{}) (*dbus.Call, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	name, objectPath := "org.freedesktop.login1", "/org/freedesktop/login1"
	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, method, flags, args...)
	if call.Err != nil {
		return nil, call.Err
	}
	return call, nil
}

func releaseSession(sid string) error {
	// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
	_, err := callLogin1("org.freedesktop.login1.Manager.ReleaseSession", dbus.FlagNoReplyExpected, sid)
	return err
}

// createSessionArgs is a wrapper struct for the Login1.Manager.CreateSession args.
// The CreateSession API arguments and response types are defined here:
// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
type createSessionArgs struct {
	uid        uint32
	pid        uint32
	service    string
	typ        string
	class      string
	desktop    string
	seat       string
	vtnr       uint32
	tty        string
	display    string
	remote     bool
	remoteUser string
	remoteHost string
	properties []struct {
		S string
		V dbus.Variant
	}
}

func (a createSessionArgs) args() []interface{} {
	return []interface{}{
		a.uid,
		a.pid,
		a.service,
		a.typ,
		a.class,
		a.desktop,
		a.seat,
		a.vtnr,
		a.tty,
		a.display,
		a.remote,
		a.remoteUser,
		a.remoteHost,
		a.properties,
	}
}

// createSessionResp is a wrapper struct for the Login1.Manager.CreateSession response.
// The CreateSession API arguments and response types are defined here:
// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
type createSessionResp struct {
	sessionID   string
	objectPath  dbus.ObjectPath
	runtimePath string
	fifoFD      dbus.UnixFD
	uid         uint32
	seatID      string
	vtnr        uint32
	existing    bool
}

func createSession(uid uint32, remoteUser, remoteHost, tty string) (createSessionResp, error) {
	a := createSessionArgs{
		uid:        uid,
		service:    "tailscaled",
		typ:        "tty",
		class:      "user",
		tty:        tty,
		remote:     true,
		remoteUser: remoteUser,
		remoteHost: remoteHost,
	}

	call, err := callLogin1("org.freedesktop.login1.Manager.CreateSession", 0, a.args()...)
	if err != nil {
		return createSessionResp{}, err
	}

	return createSessionResp{
		sessionID:   call.Body[0].(string),
		objectPath:  call.Body[1].(dbus.ObjectPath),
		runtimePath: call.Body[2].(string),
		fifoFD:      call.Body[3].(dbus.UnixFD),
		uid:         call.Body[4].(uint32),
		seatID:      call.Body[5].(string),
		vtnr:        call.Body[6].(uint32),
		existing:    call.Body[7].(bool),
	}, nil
}

func startLoginSessionLinux(logf logger.Logf, uid uint32, localUser, remoteUser, remoteHost, tty string) (func() error, error) {
	logf("starting session for user %d", uid)
	// The only way we can actually start a new session is if we are
	// running outside one and are root, which is typically the case
	// for systemd managed tailscaled.
	resp, err := createSession(uint32(uid), remoteUser, remoteHost, tty)
	if err != nil {
		// TODO(maisem): figure out if we are running in a session.
		// We can look at the DBus GetSessionByPID API.
		// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
		// For now best effort is fine.
		logf("ssh: failed to CreateSession for user %q (%d) %v", localUser, uid, err)
		return nil, nil
	}
	if !resp.existing {
		return func() error {
			return releaseSession(resp.sessionID)
		}, nil
	}
	return nil, nil
}
