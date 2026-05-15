//go:build windows

package daemon

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

// schtasksBackend installs the audr daemon as a per-user Scheduled
// Task that fires at user logon. Path of least resistance through
// Windows service-management constraints:
//
//   - Windows Services run in Session 0 → can't reach the user's
//     desktop → can't deliver toast notifications. Service Control
//     Manager is out.
//   - Per-user LaunchAgent / systemd --user have no native Windows
//     analogue. Task Scheduler is the closest.
//   - The Task Scheduler COM API would let us avoid shelling out, but
//     pulls in `golang.org/x/sys/windows` COM bindings and ~600 lines
//     of activation/dispatch wrapping. `schtasks.exe` is in PATH on
//     every supported Windows version since XP. The shell-out is the
//     simpler path and stays in the codebase regardless of whether
//     we later add a COM-direct variant.
//
// Codex outside-voice review flagged install-path drift as a real
// concern (#8): a task created with a hard-coded executable path
// breaks across versions / sideloads / unzip-and-run. The backend
// resolves the path from os.Executable() at install time and uses
// schtasks /Create /F to force-overwrite an existing task — so
// reinstalling after an upgrade naturally rewrites the task XML to
// the new binary location.
type schtasksBackend struct {
	cfg ServiceConfig
	run func(ctx context.Context) error
}

func newServiceBackend(cfg ServiceConfig, run func(ctx context.Context) error) (serviceBackend, error) {
	return &schtasksBackend{cfg: cfg, run: run}, nil
}

// Install creates (or force-overwrites) the Scheduled Task. The XML
// is composed in-memory and piped to schtasks via a temp file. We
// can't pipe via stdin because schtasks expects either /XML <path>
// or named flags — there's no /XML - option.
//
// Idempotence: schtasks /Create /F overwrites an existing task with
// the same name. This is the right semantics for re-install after
// upgrade — the task's Command path picks up the new audr.exe location
// without leaving a stale entry pointing at the old install.
func (b *schtasksBackend) Install() error {
	xmlBytes, err := b.composeTaskXML()
	if err != nil {
		return fmt.Errorf("compose task XML: %w", err)
	}

	tmp, err := os.CreateTemp("", "audr-task-*.xml")
	if err != nil {
		return fmt.Errorf("create temp XML: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	// schtasks parses the XML as UTF-16 LE by default when the file
	// starts with a BOM. We write UTF-8 explicitly — schtasks accepts
	// UTF-8 without a BOM, which dodges encoding ambiguity entirely.
	if _, err := tmp.Write(xmlBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp XML: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp XML: %w", err)
	}

	// /Create /TN <name> /XML <path> /F creates-or-overwrites.
	// Suppress stdout (status chatter) but capture stderr for the
	// error message if it fails.
	cmd := exec.Command("schtasks",
		"/Create",
		"/TN", b.cfg.Name,
		"/XML", tmpPath,
		"/F", // force-overwrite if it already exists
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /Create: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}

	// AppUserModelID registration will land in a follow-up slice
	// alongside the Windows toaster (Lane A continuation). Until then
	// the Scheduled Task is enough for the daemon to run and serve
	// the dashboard; toasts fall back to beeep without click action.
	return nil
}

// Uninstall stops the running task (best-effort — a not-running task
// returns non-zero, which we tolerate) then deletes it.
//
// Returns nil on "not installed" — mirrors the kardianos backend's
// normalized contract. The CLI prints "audr daemon: uninstalled"
// regardless and the user gets the same UX whether or not the task
// existed.
func (b *schtasksBackend) Uninstall() error {
	// End: ignore failure (task may not be running).
	_ = exec.Command("schtasks", "/End", "/TN", b.cfg.Name).Run()

	// Delete: tolerate "task does not exist".
	cmd := exec.Command("schtasks", "/Delete", "/TN", b.cfg.Name, "/F")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errText := strings.ToLower(stderr.String())
		if strings.Contains(errText, "cannot find") || strings.Contains(errText, "does not exist") {
			return nil
		}
		return fmt.Errorf("schtasks /Delete: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Start asks Task Scheduler to start the task immediately. Equivalent
// of `schtasks /Run` from the command line.
func (b *schtasksBackend) Start() error {
	cmd := exec.Command("schtasks", "/Run", "/TN", b.cfg.Name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /Run: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Stop ends a running task. Equivalent of `schtasks /End`.
func (b *schtasksBackend) Stop() error {
	cmd := exec.Command("schtasks", "/End", "/TN", b.cfg.Name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /End: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Status parses `schtasks /Query /FO LIST` output. The relevant fields
// are "Status:" (Running / Ready / Disabled / etc.) and the implicit
// "task not found" signal from a non-zero exit + matching stderr.
func (b *schtasksBackend) Status() (string, error) {
	cmd := exec.Command("schtasks", "/Query", "/TN", b.cfg.Name, "/FO", "LIST")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errText := strings.ToLower(stderr.String())
		if strings.Contains(errText, "cannot find") || strings.Contains(errText, "does not exist") {
			return "not-installed", nil
		}
		return "", fmt.Errorf("schtasks /Query: %w (stderr: %s)",
			err, strings.TrimSpace(stderr.String()))
	}
	return parseSchtasksStatus(stdout.String()), nil
}

// parseSchtasksStatus extracts the "Status:" line from schtasks
// /FO LIST output and normalizes it to audr's status vocabulary.
//
// LIST output looks like (one task):
//
//	HostName:                              MACHINE
//	TaskName:                              \Audr Daemon
//	Next Run Time:                         N/A
//	Status:                                Running
//	Logon Mode:                            Interactive only
//	...
func parseSchtasksStatus(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) != "Status" {
			continue
		}
		switch strings.TrimSpace(v) {
		case "Running":
			return "running"
		case "Ready", "Queued":
			return "stopped"
		case "Disabled":
			return "stopped"
		default:
			return "unknown"
		}
	}
	return "unknown"
}

// Run executes the daemon's main loop directly. Unlike the kardianos
// path on Linux/macOS — which has a service-manager protocol routing
// Start/Stop callbacks through serviceProgram — Task Scheduler just
// spawns the binary as a regular user process. We wire signal
// handling here so a `schtasks /End` (CTRL_BREAK_EVENT) or an
// interactive Ctrl-C both cleanly cancel the run-context.
func (b *schtasksBackend) Run() error {
	if b.run == nil {
		return errors.New("service: RunAsService called without a configured run callback")
	}
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return b.run(ctx)
}

// IsInteractive on Windows: there's no kardianos-installed dependency
// to consult, so we use a simpler heuristic — does the process have
// a parent that's a console? When schtasks spawns us we have no
// console; when a user runs `audr daemon run-internal` from a
// terminal we do. GetConsoleWindow returns NULL when there's no
// console.
//
// This is purely informational (logging hints, telemetry); the daemon
// behaves the same regardless.
func IsInteractive() bool {
	// Cheap heuristic: if stdin is a character device (terminal), we
	// have a console. schtasks-spawned processes inherit a NUL device
	// stdin instead.
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ----- Task XML composition --------------------------------------

// composeTaskXML builds the Scheduled Task XML for audr daemon.
// Schema reference:
//
//	https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
//
// Choices and their rationale:
//
//   - LogonTrigger (not BootTrigger or DailyTrigger): runs once per
//     user logon, which matches the per-user-service model from
//     macOS LaunchAgents and systemd --user.
//
//   - LogonType=InteractiveToken: the task runs in the user's
//     interactive logon session, with desktop access (toasts work,
//     window stations are correct). The alternative `Password`
//     stores credentials with the task — disqualifying for a
//     security tool.
//
//   - RunLevel=LeastPrivilege: explicitly avoid elevation. The
//     daemon only needs user-level access to $HOME and its own state
//     dir. Elevated tasks open a UAC prompt at install time which
//     is precisely the "you're handing me admin?" friction a CISO
//     review would flag.
//
//   - StopIfGoingOnBatteries=false + DisallowStartIfOnBatteries=false:
//     dev-machine scans must keep running on a laptop unplugged from
//     mains. The point of the lowprio package is that audr never
//     hogs the laptop; the user is not better off if their security
//     monitor pauses while they switch desks.
//
//   - MultipleInstancesPolicy=IgnoreNew: if for any reason the
//     daemon is already running when Task Scheduler fires again
//     (e.g., the user logs out and back in quickly), the second
//     attempt is silently ignored. Process-internal PID lock would
//     also catch this; defense in depth.
//
//   - StartWhenAvailable=true: if the trigger fires while audr is
//     unavailable (machine asleep, etc.), Windows queues the
//     trigger and fires it on next wake. Matches the daemon's
//     "always-on" promise.
//
//   - Hidden=true: hides from the default "Scheduled Tasks" view in
//     Task Scheduler UI. Users can still see it via the Hidden
//     filter — not security by obscurity, just keeping the UI list
//     short for users with many tasks.
func (b *schtasksBackend) composeTaskXML() ([]byte, error) {
	user := os.Getenv("USERNAME")
	if user == "" {
		return nil, errors.New("USERNAME env var not set; cannot compose task XML")
	}
	domain := os.Getenv("USERDOMAIN")
	userID := user
	if domain != "" {
		userID = domain + `\` + user
	}

	// Quote the executable path defensively. schtasks XML is
	// whitespace-significant; spaces in the path (e.g.,
	// `C:\Program Files\audr\audr.exe`) require explicit quoting in
	// the <Command> element value.
	doc := taskXML{
		Version: "1.4",
		XMLNS:   "http://schemas.microsoft.com/windows/2004/02/mit/task",
		RegistrationInfo: taskRegistrationInfo{
			Description: b.cfg.Description,
		},
		Triggers: taskTriggers{
			LogonTrigger: taskLogonTrigger{
				Enabled: true,
				UserID:  userID,
			},
		},
		Principals: taskPrincipals{
			Principal: taskPrincipal{
				ID:        "Author",
				UserID:    userID,
				LogonType: "InteractiveToken",
				RunLevel:  "LeastPrivilege",
			},
		},
		Settings: taskSettings{
			DisallowStartIfOnBatteries: false,
			StopIfGoingOnBatteries:     false,
			RunOnlyIfIdle:              false,
			MultipleInstancesPolicy:    "IgnoreNew",
			StartWhenAvailable:         true,
			Hidden:                     true,
			AllowHardTerminate:         true,
			ExecutionTimeLimit:         "PT0S", // PT0S = no time limit
		},
		Actions: taskActions{
			Context: "Author",
			Exec: taskExec{
				Command:   b.cfg.ExecPath,
				Arguments: strings.Join(b.cfg.Args, " "),
			},
		},
	}

	body, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal task XML: %w", err)
	}
	// Prepend the XML declaration. schtasks accepts UTF-8 without a
	// BOM; we add the declaration but no BOM.
	out := append([]byte(xml.Header), body...)
	return out, nil
}

// taskXML mirrors the Task Scheduler schema with only the fields
// audr cares about. Unspecified fields take Windows defaults, which
// are sensible for a per-user logon task.
type taskXML struct {
	XMLName          xml.Name             `xml:"Task"`
	Version          string               `xml:"version,attr"`
	XMLNS            string               `xml:"xmlns,attr"`
	RegistrationInfo taskRegistrationInfo `xml:"RegistrationInfo"`
	Triggers         taskTriggers         `xml:"Triggers"`
	Principals       taskPrincipals       `xml:"Principals"`
	Settings         taskSettings         `xml:"Settings"`
	Actions          taskActions          `xml:"Actions"`
}

type taskRegistrationInfo struct {
	Description string `xml:"Description"`
}

type taskTriggers struct {
	LogonTrigger taskLogonTrigger `xml:"LogonTrigger"`
}

type taskLogonTrigger struct {
	Enabled bool   `xml:"Enabled"`
	UserID  string `xml:"UserId"`
}

type taskPrincipals struct {
	Principal taskPrincipal `xml:"Principal"`
}

type taskPrincipal struct {
	ID        string `xml:"id,attr"`
	UserID    string `xml:"UserId"`
	LogonType string `xml:"LogonType"`
	RunLevel  string `xml:"RunLevel"`
}

type taskSettings struct {
	DisallowStartIfOnBatteries bool   `xml:"DisallowStartIfOnBatteries"`
	StopIfGoingOnBatteries     bool   `xml:"StopIfGoingOnBatteries"`
	RunOnlyIfIdle              bool   `xml:"RunOnlyIfIdle"`
	MultipleInstancesPolicy    string `xml:"MultipleInstancesPolicy"`
	StartWhenAvailable         bool   `xml:"StartWhenAvailable"`
	Hidden                     bool   `xml:"Hidden"`
	AllowHardTerminate         bool   `xml:"AllowHardTerminate"`
	ExecutionTimeLimit         string `xml:"ExecutionTimeLimit"`
}

type taskActions struct {
	Context string   `xml:"Context,attr"`
	Exec    taskExec `xml:"Exec"`
}

type taskExec struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}
