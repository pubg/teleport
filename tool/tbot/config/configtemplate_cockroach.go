/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"context"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/client/identityfile"
	"github.com/gravitational/teleport/tool/tbot/identity"
	"github.com/gravitational/trace"
)

const defaultCockroachDirName = "cockroach"

// TemplateCockroach generates certificates for CockroachDB. These are standard
// TLS certs but have specific naming requirements. We write them to a
// subdirectory to ensure naming is clear.
type TemplateCockroach struct {
	DirName string `yaml:"dir_name,omitempty"`
}

func (t *TemplateCockroach) CheckAndSetDefaults() error {
	if t.DirName == "" {
		t.DirName = defaultCockroachDirName
	}

	return nil
}

func (t *TemplateCockroach) Name() string {
	return TemplateCockroachName
}

func (t *TemplateCockroach) Describe() []FileDescription {
	return []FileDescription{
		{
			Name:  t.DirName,
			IsDir: true,
		},
	}
}

func (t *TemplateCockroach) Render(ctx context.Context, authClient auth.ClientI, currentIdentity *identity.Identity, destination *DestinationConfig) error {
	dest, err := destination.GetDestination()
	if err != nil {
		return trace.Wrap(err)
	}

	dbCAs, err := authClient.GetCertAuthorities(ctx, types.DatabaseCA, false)
	if err != nil {
		return trace.Wrap(err)
	}

	cfg := identityfile.WriteConfig{
		OutputPath: t.DirName,
		Writer: &BotConfigWriter{
			dest:    dest,
			subpath: t.DirName,
		},
		Key:    newClientKey(currentIdentity, dbCAs),
		Format: identityfile.FormatCockroach,

		// Always overwrite to avoid hitting our no-op Stat() and Remove() functions.
		OverwriteDestination: true,
	}

	files, err := identityfile.Write(cfg)
	if err != nil {
		return trace.Wrap(err)
	}

	log.Debugf("Wrote CockroachDB files: %+v", files)

	return nil
}
