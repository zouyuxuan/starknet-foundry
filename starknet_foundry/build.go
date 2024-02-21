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
	"fmt"
	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Build struct {
	Logger bard.Logger
}

func (b Build) Build(context libcnb.BuildContext) (libcnb.BuildResult, error) {
	b.Logger.Title(context.Buildpack)
	result := libcnb.NewBuildResult()
	config, err := libpak.NewConfigurationResolver(context.Buildpack, &b.Logger)
	dependency, err := libpak.NewDependencyResolver(context)
	if err != nil {
		return libcnb.BuildResult{}, err
	}
	libc, _ := config.Resolve("BP_STARKNET_FOUNDRY_LIBC")

	version, _ := config.Resolve("BP_STARKNET_FOUNDRY_VERSION")
	b.Logger.Info("fmt.Sprintf(\"starknet-foundry-%s\", libc)", fmt.Sprintf("starknet-foundry-%s", libc))
	buildDependency, _ := dependency.Resolve(fmt.Sprintf("starknet-foundry-%s", libc), version)

	dc, err := libpak.NewDependencyCache(context)
	if err != nil {
		return libcnb.BuildResult{}, fmt.Errorf("unable to create dependency cache\n%w", err)
	}
	dc.Logger = b.Logger

	scarb := NewStarknetFoundry(buildDependency, dc)
	scarb.Logger = b.Logger
	result.Layers = append(result.Layers, scarb)
	return result, nil
}
