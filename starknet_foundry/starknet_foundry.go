// Copyright (c) The Amphitheatre Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package starknet_foundry

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/crush"
	"github.com/paketo-buildpacks/libpak/effect"
	"github.com/paketo-buildpacks/libpak/sbom"
	"github.com/paketo-buildpacks/libpak/sherpa"
)

type StarknetFoundry struct {
	Version          string
	LayerContributor libpak.DependencyLayerContributor
	Logger           bard.Logger
	Executor         effect.Executor
}

func NewStarknetFoundry(dependency libpak.BuildpackDependency, cache libpak.DependencyCache) StarknetFoundry {
	contributor := libpak.NewDependencyLayerContributor(dependency, cache, libcnb.LayerTypes{
		Cache:  true,
		Launch: true,
		Build:  true,
	})
	return StarknetFoundry{
		Executor:         effect.NewExecutor(),
		Version:          dependency.Version,
		LayerContributor: contributor,
	}
}

func (s StarknetFoundry) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	s.LayerContributor.Logger = s.Logger
	return s.LayerContributor.Contribute(layer, func(artifact *os.File) (libcnb.Layer, error) {
		bin := filepath.Join(layer.Path, "bin")

		s.Logger.Bodyf("Expanding %s to %s", artifact.Name(), layer.Path)
		if err := crush.Extract(artifact, layer.Path, 1); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to expand %s\n%w", artifact.Name(), err)
		}

		sncast := filepath.Join(layer.Path, "bin", "sncast")
		if err := os.Chmod(sncast, 0755); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to chmod %s\n%w", sncast, err)
		}
		snforge := filepath.Join(layer.Path, "bin", "snforge")
		if err := os.Chmod(snforge, 0755); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to chmod %s\n%w", snforge, err)
		}

		if err := os.Setenv("PATH", sherpa.AppendToEnvVar("PATH", ":", bin)); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to set $PATH\n%w", err)
		}

		buf := &bytes.Buffer{}
		if err := s.Executor.Execute(effect.Execution{
			Command: "sncast",
			Args:    []string{"-V"},
			Stdout:  buf,
			Stderr:  buf,
		}); err != nil {
			return libcnb.Layer{}, fmt.Errorf("error executing '%s -V':\n Combined Output: %s: \n%w", sncast, buf.String(), err)
		}
		ver := strings.Split(strings.TrimSpace(buf.String()), " ")
		s.Logger.Bodyf("Checking %s version: %s", sncast, ver[1])

		buf1 := &bytes.Buffer{}
		if err := s.Executor.Execute(effect.Execution{
			Command: "snforge",
			Args:    []string{"-V"},
			Stdout:  buf1,
			Stderr:  buf1,
		}); err != nil {
			return libcnb.Layer{}, fmt.Errorf("error executing '%s -V':\n Combined Output: %s: \n%w", snforge, buf1.String(), err)
		}
		ver1 := strings.Split(strings.TrimSpace(buf.String()), " ")
		s.Logger.Bodyf("Checking %s version: %s", snforge, ver1[1])
		sbomPath := layer.SBOMPath(libcnb.SyftJSON)
		dep := sbom.NewSyftDependency(layer.Path, []sbom.SyftArtifact{
			{
				ID:      "starknet-foundry",
				Name:    "StarknetFoundry",
				Version: ver[1],
				Type:    "UnknownPackage",
				FoundBy: "amp-buildpacks/starknet-foundry",
				Locations: []sbom.SyftLocation{
					{Path: "amp-buildpacks/starknet-foundry/starknet-foundry/starknet-foundry.go"},
				},
				Licenses: []string{"MIT"},
				CPEs:     []string{fmt.Sprintf("cpe:2.3:a:foundry:foundry:%s:*:*:*:*:*:*:*", ver[1])},
				PURL:     fmt.Sprintf("pkg:generic/starknet-foundry@%s", ver[1]),
			},
		})
		s.Logger.Debugf("Writing Syft SBOM at %s: %+v", sbomPath, dep)
		if err := dep.WriteTo(sbomPath); err != nil {
			return libcnb.Layer{}, fmt.Errorf("unable to write SBOM\n%w", err)
		}
		return layer, nil
	})
}

func (s StarknetFoundry) Name() string {
	return s.LayerContributor.LayerName()
}
