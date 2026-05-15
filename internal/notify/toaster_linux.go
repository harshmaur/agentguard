//go:build linux

package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

// linuxToaster talks directly to org.freedesktop.Notifications via
// godbus. Unlike beeep's Notify (which omits the actions argument),
// this sends each notification with a "default" action so clicking
// the toast emits an ActionInvoked signal that we route back to a
// caller-supplied OnClick handler.
//
// Implements LifecycleToaster: Run blocks listening for signals;
// Close releases the dbus connection. Notifier.Run / Notifier.Close
// drive the lifecycle.
//
// Why direct dbus instead of layering on beeep:
//
//   - beeep.Notify deliberately omits actions (the README says it
//     keeps the API minimal). Adding actions requires bypassing it.
//   - The ActionInvoked signal is broadcast to anyone listening on
//     the session bus — we need our own connection to subscribe.
//     Doing both the Notify call AND the listener on the same
//     connection is simpler than coordinating two.
type linuxToaster struct {
	conn    *dbus.Conn
	onClick OnClick

	mu       sync.Mutex
	ownedIDs map[uint32]struct{}
}

// newLinuxToaster opens a dbus connection to the session bus and
// returns a toaster ready to send notifications with actions.
// onClick is invoked when the user clicks any audr-attributed
// notification. nil onClick disables the click integration (toasts
// still display, clicks just no-op).
func newLinuxToaster(onClick OnClick) (*linuxToaster, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("notify: open dbus session: %w", err)
	}
	return &linuxToaster{
		conn:     conn,
		onClick:  onClick,
		ownedIDs: map[uint32]struct{}{},
	}, nil
}

// Toast sends a notification with a "default" action so the entire
// toast is clickable. Implements Toaster.
func (lt *linuxToaster) Toast(title, body string) error {
	obj := lt.conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	// org.freedesktop.Notifications.Notify signature:
	//
	//   STRING app_name
	//   UINT32 replaces_id
	//   STRING app_icon
	//   STRING summary
	//   STRING body
	//   ARRAY<STRING> actions
	//   DICT<STRING,VARIANT> hints
	//   INT32 expire_timeout
	//   → UINT32 id
	//
	// actions is a flat list of [key1, label1, key2, label2, ...].
	// "default" is the magic key that maps to "user clicked the
	// notification body itself" rather than a separate action button.
	// Some notification servers (e.g. notify-osd) ignore actions
	// entirely; others (gnome-shell, KDE) route the click through.
	actions := []string{"default", "Open dashboard"}
	hints := map[string]dbus.Variant{
		// "resident" keeps the notification in the tray until
		// dismissed or clicked. Useful for CRITICAL alerts — if
		// the user is away from the screen, the toast doesn't time
		// out and disappear.
		"resident": dbus.MakeVariant(true),
	}
	var id uint32
	call := obj.Call("org.freedesktop.Notifications.Notify", 0,
		"audr",            // app_name — matches our identity in `gsettings` notification preferences
		uint32(0),         // replaces_id (0 = new notification)
		"",                // app_icon (no icon for v1)
		title,             // summary
		body,              // body
		actions,           // actions
		hints,             // hints
		int32(-1),         // expire_timeout (-1 = server default)
	)
	if call.Err != nil {
		return fmt.Errorf("notify: dbus Notify: %w", call.Err)
	}
	if err := call.Store(&id); err != nil {
		return fmt.Errorf("notify: parse Notify reply: %w", err)
	}
	lt.mu.Lock()
	lt.ownedIDs[id] = struct{}{}
	lt.mu.Unlock()
	return nil
}

// Run subscribes to ActionInvoked + NotificationClosed signals and
// dispatches to onClick for clicks on audr notifications. Blocks
// until ctx cancels. Implements LifecycleToaster.
//
// Filters by notification ID — we track every ID we sent in
// ownedIDs and ignore signals for IDs that didn't come from audr
// (e.g. someone else's notification on the same session bus).
func (lt *linuxToaster) Run(ctx context.Context) error {
	if lt.conn == nil {
		return errors.New("notify: linuxToaster.Run with nil dbus connection")
	}
	if err := lt.conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Notifications"),
		dbus.WithMatchMember("ActionInvoked"),
	); err != nil {
		return fmt.Errorf("notify: subscribe ActionInvoked: %w", err)
	}
	if err := lt.conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Notifications"),
		dbus.WithMatchMember("NotificationClosed"),
	); err != nil {
		// Not fatal — clicks still work without close-tracking.
		_ = err
	}
	sigCh := make(chan *dbus.Signal, 16)
	lt.conn.Signal(sigCh)
	defer lt.conn.RemoveSignal(sigCh)

	for {
		select {
		case <-ctx.Done():
			return nil
		case sig, ok := <-sigCh:
			if !ok {
				return nil
			}
			if sig == nil {
				continue
			}
			switch sig.Name {
			case "org.freedesktop.Notifications.ActionInvoked":
				lt.handleActionInvoked(sig)
			case "org.freedesktop.Notifications.NotificationClosed":
				lt.handleNotificationClosed(sig)
			}
		}
	}
}

func (lt *linuxToaster) handleActionInvoked(sig *dbus.Signal) {
	// Signal body shape: (UINT32 id, STRING action_key)
	if len(sig.Body) < 2 {
		return
	}
	id, ok := sig.Body[0].(uint32)
	if !ok {
		return
	}
	lt.mu.Lock()
	_, ours := lt.ownedIDs[id]
	lt.mu.Unlock()
	if !ours {
		return
	}
	// We register only one action ("default") so the action_key
	// check is defensive — if a future notification daemon emits
	// some other action_key for our id, ignore it.
	actionKey, _ := sig.Body[1].(string)
	if actionKey != "default" {
		return
	}
	if lt.onClick != nil {
		// Run the click handler in a goroutine so a slow handler
		// (browser-open via xdg-open can take 100s of ms) doesn't
		// block the signal loop from consuming the next event.
		go lt.onClick()
	}
}

func (lt *linuxToaster) handleNotificationClosed(sig *dbus.Signal) {
	// Body: (UINT32 id, UINT32 reason). Reason: 1=expired,
	// 2=dismissed-by-user, 3=closed-by-call, 4=undefined. We don't
	// care WHY — we just want to forget the ID so ownedIDs doesn't
	// grow unbounded over a long daemon lifetime.
	if len(sig.Body) < 1 {
		return
	}
	id, ok := sig.Body[0].(uint32)
	if !ok {
		return
	}
	lt.mu.Lock()
	delete(lt.ownedIDs, id)
	lt.mu.Unlock()
}

// SupportsClickAction reports true when this toaster will route
// clicks back via OnClick. On Linux that's contingent on (a) a live
// dbus session bus (set at constructor time) and (b) a non-nil
// OnClick callback. Implements ClickableToaster.
func (lt *linuxToaster) SupportsClickAction() bool {
	return lt.conn != nil && lt.onClick != nil
}

// Close releases the dbus connection. Implements LifecycleToaster.
// Idempotent.
func (lt *linuxToaster) Close() error {
	if lt.conn == nil {
		return nil
	}
	err := lt.conn.Close()
	lt.conn = nil
	return err
}

// defaultToaster on Linux: try the dbus path; fall back to beeep on
// any setup failure so a missing dbus session doesn't break the
// daemon's startup entirely.
func defaultToaster(onClick OnClick) Toaster {
	lt, err := newLinuxToaster(onClick)
	if err != nil {
		// Fall back to beeep — same behavior as pre-v0.5.8 (no
		// click integration, but at least toasts display).
		return beeepToaster{}
	}
	return lt
}
