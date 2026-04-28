package builtin

import (
	"testing"

	"github.com/agentguard/agentguard/internal/parse"
)

func TestRule_GHAWriteAllPermissions(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantFires int
	}{
		{
			name:      "top-level write-all fires",
			yaml:      "name: x\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
			wantFires: 1,
		},
		{
			name:      "explicit minimal does not fire",
			yaml:      "name: x\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/repo/.github/workflows/x.yml", []byte(tt.yaml))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "gha-write-all-permissions" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

func TestRule_GHASecretsInAgentStep(t *testing.T) {
	yaml := `name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: claude review
        uses: anthropics/claude-code-action@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
`
	doc := parse.Parse("/repo/.github/workflows/x.yml", []byte(yaml))
	fires := 0
	for _, id := range applyRule(doc) {
		if id == "gha-secrets-in-agent-step" {
			fires++
		}
	}
	if fires == 0 {
		t.Errorf("expected secrets-in-agent-step to fire; rules fired: %v", applyRule(doc))
	}
}
