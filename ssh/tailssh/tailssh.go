// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// TODO(bradfitz): this is all very temporary as code is temporarily
// being moved around; it will be restructured and documented in
// following commits.

// Handle handles an SSH connection from c.
func Handle(logf logger.Logf, lb *ipnlocal.LocalBackend, c net.Conn) error {
	tsd, err := os.Executable()
	if err != nil {
		return err
	}
	srv := &server{lb, logf, tsd}
	ss, err := srv.newSSHServer()
	if err != nil {
		return err
	}
	ss.HandleConn(c)
	return nil
}

func (srv *server) newSSHServer() (*ssh.Server, error) {
	ss := &ssh.Server{
		Handler:           srv.handleSSH,
		RequestHandlers:   map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
		ChannelHandlers:   map[string]ssh.ChannelHandler{},
	}
	for k, v := range ssh.DefaultRequestHandlers {
		ss.RequestHandlers[k] = v
	}
	for k, v := range ssh.DefaultChannelHandlers {
		ss.ChannelHandlers[k] = v
	}
	for k, v := range ssh.DefaultSubsystemHandlers {
		ss.SubsystemHandlers[k] = v
	}
	keys, err := srv.lb.GetSSH_HostKeys()
	if err != nil {
		return nil, err
	}
	for _, signer := range keys {
		ss.AddHostKey(signer)
	}
	return ss, nil
}

type server struct {
	lb             *ipnlocal.LocalBackend
	logf           logger.Logf
	tailscaledPath string
}

var debugPolicyFile = envknob.String("TS_DEBUG_SSH_POLICY_FILE")

// sshPolicy returns the SSHPolicy for current node.
// If there is no SSHPolicy in the netmap, it returns a debugPolicy
// if one is defined.
func (srv *server) sshPolicy() (_ *tailcfg.SSHPolicy, ok bool) {
	lb := srv.lb
	nm := lb.NetMap()
	if nm == nil {
		return nil, false
	}
	if pol := nm.SSHPolicy; pol != nil {
		return pol, true
	}
	if debugPolicyFile != "" {
		f, err := os.ReadFile(debugPolicyFile)
		if err != nil {
			srv.logf("error reading debug SSH policy file: %v", err)
			return nil, false
		}
		p := new(tailcfg.SSHPolicy)
		if err := json.Unmarshal(f, p); err != nil {
			srv.logf("invalid JSON in %v: %v", debugPolicyFile, err)
			return nil, false
		}
		return p, true
	}
	return nil, false
}

func asTailscaleIPPort(a net.Addr) (netaddr.IPPort, error) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netaddr.IPPort{}, fmt.Errorf("non-TCP addr %T %v", a, a)
	}
	tanetaddr, ok := netaddr.FromStdIP(ta.IP)
	if !ok {
		return netaddr.IPPort{}, fmt.Errorf("unparseable addr %v", ta.IP)
	}
	if !tsaddr.IsTailscaleIP(tanetaddr) {
		return netaddr.IPPort{}, fmt.Errorf("non-Tailscale addr %v", ta.IP)
	}
	return netaddr.IPPortFrom(tanetaddr, uint16(ta.Port)), nil
}

// evaluatePolicy returns the SSHAction after evaluating the sshUser and
// remoteAddr against the SSHPolicy. remoteAddr must be a Tailscale IP.
func (srv *server) evaluatePolicy(sshUser string, localAddr, remoteAddr net.Addr) (*tailcfg.SSHAction, *sshConnInfo, error) {
	logf := srv.logf
	lb := srv.lb
	logf("Handling SSH from %v for user %v", remoteAddr, sshUser)

	pol, ok := srv.sshPolicy()
	if !ok {
		return nil, nil, fmt.Errorf("tsshd: rejecting connection; no SSH policy")
	}

	srcIPP, err := asTailscaleIPPort(remoteAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("tsshd: rejecting: %w", err)
	}
	dstIPP, err := asTailscaleIPPort(localAddr)
	if err != nil {
		return nil, nil, err
	}
	node, uprof, ok := lb.WhoIs(srcIPP)
	if !ok {
		return nil, nil, fmt.Errorf("Hello, %v. I don't know who you are.\n", srcIPP)
	}

	ci := &sshConnInfo{
		now:     time.Now(),
		sshUser: sshUser,
		src:     srcIPP,
		dst:     dstIPP,
		node:    node,
		uprof:   &uprof,
	}
	a, localUser, ok := evalSSHPolicy(pol, ci)
	if !ok {
		return nil, nil, fmt.Errorf("ssh: access denied for %q from %v", uprof.LoginName, ci.src.IP())
	}
	ci.localUser = localUser
	return a, ci, nil
}

// handleSSH is invoked when a new SSH connection attempt is made.
func (srv *server) handleSSH(s ssh.Session) {
	logf := srv.logf

	sshUser := s.User()
	action, ci, err := srv.evaluatePolicy(sshUser, s.LocalAddr(), s.RemoteAddr())
	if err != nil {
		logf(err.Error())
		s.Exit(1)
		return
	}
	if action.Message != "" {
		io.WriteString(s.Stderr(), strings.Replace(action.Message, "\n", "\r\n", -1))
	}
	if action.Reject {
		logf("ssh: access denied for %q from %v", ci.uprof.LoginName, ci.src.IP())
		s.Exit(1)
		return
	}
	if !action.Accept || action.HoldAndDelegate != "" {
		fmt.Fprintf(s, "TODO: other SSHAction outcomes")
		s.Exit(1)
		return
	}
	lu, err := user.Lookup(ci.localUser)
	if err != nil {
		logf("ssh: user Lookup %q: %v", ci.localUser, err)
		s.Exit(1)
		return
	}

	var ctx context.Context = context.Background()
	if action.SesssionDuration != 0 {
		sctx := newSSHContext()
		ctx = sctx
		t := time.AfterFunc(action.SesssionDuration, func() {
			sctx.CloseWithError(userVisibleError{
				fmt.Sprintf("Session timeout of %v elapsed.", action.SesssionDuration),
				context.DeadlineExceeded,
			})
		})
		defer t.Stop()
	}
	srv.handleAcceptedSSH(ctx, s, ci, lu)
}

func (srv *server) handleSessionTermination(ctx context.Context, s ssh.Session, ci *sshConnInfo, cmd *exec.Cmd) {
	<-ctx.Done()
	err := ctx.Err()
	if serr, ok := err.(SSHTerminationError); ok {
		msg := serr.SSHTerminationMessage()
		if msg != "" {
			io.WriteString(s.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
		}
	}
	srv.logf("terminating SSH session from %v: %v", ci.src.IP(), err)
	cmd.Process.Kill()
}

// handleAcceptedSSH handles s once it's been accepted and determined
// that it should run as local system user lu.
//
// When ctx is done, the session is forcefully terminated. If its Err
// is an SSHTerminationError, its SSHTerminationMessage is sent to the
// user.
func (srv *server) handleAcceptedSSH(ctx context.Context, s ssh.Session, ci *sshConnInfo, lu *user.User) {
	logf := srv.logf
	localUser := lu.Username

	if euid := os.Geteuid(); euid != 0 {
		if lu.Uid != fmt.Sprint(euid) {
			logf("ssh: can't switch to user %q from process euid %v", localUser, euid)
			fmt.Fprintf(s, "can't switch user\n")
			s.Exit(1)
			return
		}
	}

	shell := loginShell(lu.Uid)
	var args []string
	if rawCmd := s.RawCommand(); rawCmd != "" {
		args = []string{"-c", rawCmd}
	}

	cmd := newSSHChildCommand(ctx, lu.Uid, ci, srv.tailscaledPath, shell, args)
	cmd.Dir = lu.HomeDir
	cmd.Env = append(cmd.Env, envForUser(lu)...)
	cmd.Env = append(cmd.Env, s.Environ()...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("SSH_CLIENT=%s %d %d", ci.src.IP(), ci.src.Port(), ci.dst.Port()),
		fmt.Sprintf("SSH_CONNECTION=%s %d %s %d", ci.src.IP(), ci.src.Port(), ci.dst.IP(), ci.dst.Port()),
	)
	logf("Running: %q, %v", cmd.Args, cmd.Env)
	stdin, stdout, stderr, err := startChild(s, cmd)
	if err != nil {
		logf("start failed: %v", err.Error())
		s.Exit(1)
		return
	}
	if ctx.Done() != nil {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go srv.handleSessionTermination(ctx, s, ci, cmd)
	}
	go func() {
		_, err := io.Copy(stdin, s)
		logf("ssh: stdin copy: %v", err)
		stdin.Close()
	}()
	go func() {
		_, err := io.Copy(s, stdout)
		logf("ssh: stdout copy: %v", err)
	}()
	if stderr != nil {
		go func() {
			_, err := io.Copy(s.Stderr(), stderr)
			logf("ssh: stderr copy: %v", err)
		}()
	}
	err = cmd.Wait()
	if err == nil {
		logf("ssh: Wait: ok")
		s.Exit(0)
		return
	}
	if ee, ok := err.(*exec.ExitError); ok {
		code := ee.ProcessState.ExitCode()
		logf("ssh: Wait: code=%v", code)
		s.Exit(code)
		return
	}

	logf("ssh: Wait: %v", err)
	s.Exit(1)
	return
}

type sshConnInfo struct {
	// now is the time to consider the present moment for the
	// purposes of rule evaluation.
	now time.Time

	// sshUser is the requested local SSH username ("root", "alice", etc).
	sshUser string

	// src is the Tailscale IP that the connection came from.
	src netaddr.IPPort

	// dst is the Tailscale IP that the connection came for.
	dst netaddr.IPPort

	// node is srcIP's node.
	node *tailcfg.Node

	// uprof is node's UserProfile.
	uprof *tailcfg.UserProfile

	// localUser is the username of the local user as configured
	// by the policy. This is filled in after policy evaluation.
	localUser string
}

func evalSSHPolicy(pol *tailcfg.SSHPolicy, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, ok bool) {
	for _, r := range pol.Rules {
		if a, localUser, err := matchRule(r, ci); err == nil {
			return a, localUser, true
		}
	}
	return nil, "", false
}

// internal errors for testing; they don't escape to callers or logs.
var (
	errNilRule        = errors.New("nil rule")
	errNilAction      = errors.New("nil action")
	errRuleExpired    = errors.New("rule expired")
	errPrincipalMatch = errors.New("principal didn't match")
	errUserMatch      = errors.New("user didn't match")
)

func matchRule(r *tailcfg.SSHRule, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, err error) {
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if r.RuleExpires != nil && ci.now.After(*r.RuleExpires) {
		return nil, "", errRuleExpired
	}
	if !matchesPrincipal(r.Principals, ci) {
		return nil, "", errPrincipalMatch
	}
	if !r.Action.Reject || r.SSHUsers != nil {
		localUser = mapLocalUser(r.SSHUsers, ci.sshUser)
		if localUser == "" {
			return nil, "", errUserMatch
		}
	}
	return r.Action, localUser, nil
}

func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string) (localUser string) {
	if v, ok := ruleSSHUsers[reqSSHUser]; ok {
		return v
	}
	return ruleSSHUsers["*"]
}

func matchesPrincipal(ps []*tailcfg.SSHPrincipal, ci *sshConnInfo) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.Any {
			return true
		}
		if !p.Node.IsZero() && ci.node != nil && p.Node == ci.node.StableID {
			return true
		}
		if p.NodeIP != "" {
			if ip, _ := netaddr.ParseIP(p.NodeIP); ip == ci.src.IP() {
				return true
			}
		}
		if p.UserLogin != "" && ci.uprof != nil && ci.uprof.LoginName == p.UserLogin {
			return true
		}
	}
	return false
}

func loginShell(uid string) string {
	switch runtime.GOOS {
	case "linux":
		out, _ := exec.Command("getent", "passwd", uid).Output()
		// out is "root:x:0:0:root:/root:/bin/bash"
		f := strings.SplitN(string(out), ":", 10)
		if len(f) > 6 {
			return strings.TrimSpace(f[6]) // shell
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/bash"
}

func envForUser(u *user.User) []string {
	return []string{
		fmt.Sprintf("SHELL=" + loginShell(u.Uid)),
		fmt.Sprintf("USER=" + u.Username),
		fmt.Sprintf("HOME=" + u.HomeDir),
	}
}
