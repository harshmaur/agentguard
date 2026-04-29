package parse

import (
	"encoding/json"
	"fmt"
)

func parsePackageJSON(raw []byte) (*PackageJSON, error) {
	var top struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("package.json parse: %w", err)
	}
	return &PackageJSON{
		Name:                 top.Name,
		Version:              top.Version,
		Dependencies:         top.Dependencies,
		DevDependencies:      top.DevDependencies,
		OptionalDependencies: top.OptionalDependencies,
		PeerDependencies:     top.PeerDependencies,
	}, nil
}
