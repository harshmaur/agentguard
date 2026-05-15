package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/harshmaur/audr/internal/policy"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage the audr policy overlay (~/.audr/policy.yaml)",
		Long: `Manage the user-editable policy overlay that adjusts how built-in
rules behave. The policy file at ~/.audr/policy.yaml lets you:

  * Disable rules globally
  * Override per-rule severity
  * Narrow per-rule scope (include / exclude glob lists)
  * Define named allowlists rules can consult
  * Suppress specific findings by (rule, path) with a required reason

The daemon re-reads the file at the top of every scan cycle (no
restart needed). The one-shot 'audr scan' CLI runs with no policy
overlay; only the daemon honors it.

Built-in detection logic is NOT user-editable in v1.2 — this is a
policy overlay, not a rules-as-data refactor. Custom rule definitions
land in v1.3 (see TODOS.md).`,
	}
	cmd.AddCommand(newPolicyShowCmd())
	cmd.AddCommand(newPolicyPathCmd())
	cmd.AddCommand(newPolicyEditCmd())
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyInitCmd())
	return cmd
}

func newPolicyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the current policy file (~/.audr/policy.yaml)",
		Long: `Print the current contents of ~/.audr/policy.yaml. Use this in
support / debugging conversations to confirm what the daemon will
load on its next scan cycle.

When no policy file exists, prints a one-line note instead of
erroring — the daemon scans with built-in defaults in that case.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := policy.Path()
			if err != nil {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(cmd.OutOrStdout(),
						"audr: no policy file at %s — daemon scans with built-in defaults.\n",
						path)
					fmt.Fprintf(cmd.OutOrStdout(),
						"audr: run 'audr policy init' to create a starter file.\n")
					return nil
				}
				return fmt.Errorf("read %s: %w", path, err)
			}
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
}

func newPolicyPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the absolute path to the policy file",
		Long: `Print the policy file path. Useful in scripts:

  $EDITOR "$(audr policy path)"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := policy.Path()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
			return nil
		},
	}
}

func newPolicyEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Open the policy file in $EDITOR (or VS Code / vi)",
		Long: `Open ~/.audr/policy.yaml in the user's editor of choice:

  1. $VISUAL (if set)
  2. $EDITOR (if set)
  3. 'code' (VS Code) when on PATH
  4. 'vi' as the universal fallback

On exit the file is re-validated. A malformed save prints the parse
error but leaves the file in place — the daemon's auto-fallback
will scan with built-in defaults until the user fixes it.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := policy.Path()
			if err != nil {
				return err
			}
			// Create an empty starter file if absent so $EDITOR doesn't
			// open a blank buffer with no path resolution.
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					return fmt.Errorf("create policy dir: %w", err)
				}
				if err := policy.Save(path, policy.DefaultPolicy()); err != nil {
					return fmt.Errorf("initialize empty policy: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"audr: created %s with default (empty) policy\n", path)
			}

			editor := chooseEditor()
			c := exec.Command(editor, path)
			c.Stdin = os.Stdin
			c.Stdout = cmd.OutOrStdout()
			c.Stderr = cmd.ErrOrStderr()
			if err := c.Run(); err != nil {
				return fmt.Errorf("editor %q: %w", editor, err)
			}

			// Re-validate after the editor exits. Don't auto-fix —
			// surface the error so the user knows their save isn't
			// going to do what they expect.
			if _, err := policy.Load(path); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"audr: warning — policy file failed validation: %v\n", err)
				fmt.Fprintf(cmd.ErrOrStderr(),
					"audr: the daemon will scan with built-in defaults until this is fixed.\n")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "audr: policy file validated cleanly.")
			return nil
		},
	}
}

func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate ~/.audr/policy.yaml (or a path passed as an argument)",
		Long: `Parse and validate the policy file. Returns exit code 0 when valid,
non-zero with a diagnostic when malformed. Useful in CI:

  audr policy validate ~/.audr/policy.yaml || exit 1

When no argument is given, validates the default ~/.audr/policy.yaml.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) >= 1 {
				path = args[0]
			} else {
				p, err := policy.Path()
				if err != nil {
					return err
				}
				path = p
			}
			p, err := policy.Load(path)
			if err != nil {
				return fmt.Errorf("invalid: %w", err)
			}
			if err := p.Validate(); err != nil {
				return fmt.Errorf("invalid: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audr: %s validates cleanly.\n", path)
			// Print a one-line summary so the user has confirmation
			// the validator actually parsed something non-trivial.
			fmt.Fprintf(cmd.OutOrStdout(),
				"audr: %d rule overrides · %d allowlists · %d suppressions\n",
				len(p.Rules), len(p.Allowlists), len(p.Suppressions))
			return nil
		},
	}
}

func newPolicyInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an empty ~/.audr/policy.yaml with the canonical header",
		Long: `Create a starter policy file. Idempotent unless --force is given —
an existing file is left alone with a one-line note.

The starter file contains the canonical header comment explaining the
regeneration contract and nothing else (no rule overrides). Edit it
to your taste; the daemon picks up changes on its next scan cycle.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := policy.Path()
			if err != nil {
				return err
			}
			if _, err := os.Stat(path); err == nil && !force {
				fmt.Fprintf(cmd.OutOrStdout(),
					"audr: %s already exists. Pass --force to overwrite.\n", path)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return fmt.Errorf("create policy dir: %w", err)
			}
			if err := policy.Save(path, policy.DefaultPolicy()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audr: wrote starter policy to %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	return cmd
}

// chooseEditor picks the user's preferred editor. Order matches the
// docstring on newPolicyEditCmd. Windows has its own default chain
// because $EDITOR is uncommon and 'vi' isn't typically on PATH.
func chooseEditor() string {
	if e := strings.TrimSpace(os.Getenv("VISUAL")); e != "" {
		return e
	}
	if e := strings.TrimSpace(os.Getenv("EDITOR")); e != "" {
		return e
	}
	if _, err := exec.LookPath("code"); err == nil {
		return "code"
	}
	if runtime.GOOS == "windows" {
		// Windows fallback — notepad is universal.
		return "notepad"
	}
	return "vi"
}

// Compile-time hint to keep io import in use if a future enhancement
// streams editor output. Without this the build flips between
// "imported and not used" depending on which fallbacks we keep.
var _ io.Writer = os.Stdout
