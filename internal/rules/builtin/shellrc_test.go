package builtin

import (
	"testing"

	"github.com/harshmaur/agentguard/internal/parse"
)

func TestRule_ShellrcSecretExport(t *testing.T) {
	rc := `# zshrc
export GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export PATH=/usr/local/bin
`
	doc := parse.Parse("/home/u/.zshrc", []byte(rc))
	fires := 0
	for _, id := range applyRule(doc) {
		if id == "shellrc-secret-export" {
			fires++
		}
	}
	if fires == 0 {
		t.Errorf("shellrc with token should trigger; rules fired: %v", applyRule(doc))
	}
}

// v0.1.4: regression tests for the shellrc patterns that v0.1.0-0.1.3 missed
// on a real Mac scan. Three production tokens were present in .zprofile, only
// one was caught. Each case below corresponds to one of the missed shapes.
func TestRule_ShellrcSecretExport_v014ExtendedShapes(t *testing.T) {
	cases := []struct {
		name string
		rc   string
		want bool
	}{
		{
			// Synthetic placeholder. The original v0.1.4 fixture was a real
			// captured token; rotated 2026-04-28 and replaced with a value
			// that matches the rule's regex without resembling any real
			// GitLab PAT (no `.NN.<hash>` checksum suffix). See AGENTS.md.
			name: "GitLab personal access token via glpat- prefix",
			rc: `export SA_GITLAB_REGISTRY_TOKEN=glpat-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`,
			want: true,
		},
		{
			name: "GitLab project trigger token via glptt- prefix",
			rc:   `export GL_PROJECT_TOKEN=glptt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` + "\n",
			want: true,
		},
		{
			name: "Hugging Face hf_ prefix",
			rc:   `export HF_API_TOKEN=hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` + "\n",
			want: true,
		},
		{
			name: "modern npm token npm_ prefix",
			rc:   `export NPM_TOKEN=npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` + "\n",
			want: true,
		},
		{
			name: "UUID value with _AUTHTOKEN env name suffix (Mac scan case)",
			rc:   `export FONTAWESOME_REGISTRY_AUTHTOKEN=C407A854-DEF2-439E-B083-1FC313125858` + "\n",
			want: true,
		},
		{
			name: "name suffix _SECRET with non-trivial value",
			rc:   `export DATABASE_PASSWORD_SECRET=fjkdLKJ34lkj9fkdSL34kJ` + "\n",
			want: true,
		},
		{
			name: "PATH-like value with _PATH suffix (must NOT fire — _PATH is not a credential suffix)",
			rc:   `export NODE_PATH=/usr/local/lib/node_modules` + "\n",
			want: false,
		},
		{
			name: "short value should NOT trigger name-suffix path",
			rc:   `export FOO_TOKEN=v2` + "\n",
			want: false,
		},
		{
			name: "boolean-like value should NOT trigger",
			rc:   `export DEBUG_KEY=true` + "\n",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/home/u/.zprofile", []byte(c.rc))
			fired := false
			for _, id := range applyRule(doc) {
				if id == "shellrc-secret-export" {
					fired = true
					break
				}
			}
			if fired != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", fired, c.want, applyRule(doc))
			}
		})
	}
}
