package parse

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseWorkflow parses a GitHub Actions workflow YAML into the subset of
// structure rules care about: top-level permissions, jobs, steps, env, run/uses.
//
// Note: GHA YAML uses the unusual on: keyword which yaml.v3 will try to parse
// as a boolean true under default settings, so we use the dynamic any path.
func parseWorkflow(raw []byte) (*Workflow, error) {
	var top map[string]any
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("workflow yaml: %w", err)
	}
	w := &Workflow{
		Jobs: map[string]Job{},
	}
	if name, ok := top["name"].(string); ok {
		w.Name = name
	}

	w.Permissions = stringMap(top["permissions"])

	if jobs, ok := top["jobs"].(map[string]any); ok {
		for jobName, jobAny := range jobs {
			jobMap, ok := jobAny.(map[string]any)
			if !ok {
				continue
			}
			job := Job{
				Name:        jobName,
				Permissions: stringMap(jobMap["permissions"]),
			}
			if runsOn, ok := jobMap["runs-on"].(string); ok {
				job.RunsOn = []string{runsOn}
			} else if arr, ok := jobMap["runs-on"].([]any); ok {
				for _, x := range arr {
					if s, ok := x.(string); ok {
						job.RunsOn = append(job.RunsOn, s)
					}
				}
			}
			if steps, ok := jobMap["steps"].([]any); ok {
				for _, sa := range steps {
					sm, ok := sa.(map[string]any)
					if !ok {
						continue
					}
					st := Step{
						Env:  stringMap(sm["env"]),
						With: stringMap(sm["with"]),
					}
					if v, ok := sm["name"].(string); ok {
						st.Name = v
					}
					if v, ok := sm["uses"].(string); ok {
						st.Uses = v
					}
					if v, ok := sm["run"].(string); ok {
						st.Run = v
					}
					job.Steps = append(job.Steps, st)
				}
			}
			w.Jobs[jobName] = job
		}
	}
	return w, nil
}

// stringMap coerces an any into map[string]string, skipping non-string values.
// Used for `env:`, `permissions:`, and `with:` blocks where values are typically
// strings but may also be true/false (we coerce to string forms).
func stringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		// permissions: "write-all" shorthand
		if s, ok := v.(string); ok {
			return map[string]string{"_": s}
		}
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		switch vv := val.(type) {
		case string:
			out[k] = vv
		case bool:
			out[k] = fmt.Sprintf("%v", vv)
		case int, int64, float64:
			out[k] = fmt.Sprintf("%v", vv)
		default:
			out[k] = strings.TrimSpace(fmt.Sprintf("%v", vv))
		}
	}
	return out
}
