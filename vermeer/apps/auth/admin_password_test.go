/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. The ASF
licenses this file to You under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vermeer/apps/common"
)

func isolateAdminPasswordConfig(t *testing.T) {
	t.Helper()
	previousFactory, previousSecure, previousPassword := factory, secureFactory, adminPassword
	t.Cleanup(func() { factory, secureFactory, adminPassword = previousFactory, previousSecure, previousPassword })
	for _, key := range []string{"auth_token_factor", "auth_token_factor_file", "admin_password_file"} {
		previous := common.GetConfigDefault(key, "")
		common.SetConfig(key, "")
		t.Cleanup(func() { common.SetConfig(key, previous) })
	}
	for _, name := range []string{"VERMEER_AUTH_TOKEN_FACTOR_FILE", "VERMEER_ADMIN_PASSWORD_FILE"} {
		t.Setenv(name, "")
	}
}

func writeAdminFixture(t *testing.T, name, data string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestAdminPasswordFilePrecedenceAndRotation(t *testing.T) {
	isolateAdminPasswordConfig(t)
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", writeAdminFixture(t, "factor", "synthetic-admin-ui-signing-factor"))
	const configuredPassword = "ConfigPassword16"
	const initialPassword = " First密碼\"\\Value "
	configured := writeAdminFixture(t, "configured-password", configuredPassword)
	override := writeAdminFixture(t, "environment-password", initialPassword)
	common.SetConfig("admin_password_file", configured)
	t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", override)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ExchangeAdminPassword(configuredPassword); ok {
		t.Fatal("environment password file must take precedence")
	}
	encoded, ok := ExchangeAdminPassword(initialPassword)
	if !ok || encoded == initialPassword {
		t.Fatal("password must exchange for a separate opaque session token")
	}
	session := ToTokenBase58(encoded)
	now := time.Now().Unix()
	if session == nil || session.User != "admin" || session.Space != "$DEFAULT" ||
		session.Time < now-1 || session.Time > now || !ValidLoginToken(session) {
		t.Fatal("password login must issue a current v2 administrator session")
	}
	if !strings.HasPrefix(session.Digest, "v2:") || AdminSessionMaxAge != 24*60*60 {
		t.Fatal("native UI sessions must use v2 signatures and the 24 hour token lifetime")
	}
	if ValidLoginToken(ToTokenBase58(initialPassword)) {
		t.Fatal("short passwords must not authenticate as API tokens")
	}
	const rotatedPassword = "RotatedAdmin1234"
	if err := os.WriteFile(override, []byte(rotatedPassword), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ExchangeAdminPassword(initialPassword); ok {
		t.Fatal("old password must stop working after a reload")
	}
	if _, ok := ExchangeAdminPassword(rotatedPassword); !ok {
		t.Fatal("rotated password must authenticate")
	}
	if !ValidLoginToken(session) {
		t.Fatal("password rotation alone must not rotate the token signing factor")
	}
	session.Time = time.Now().Unix() - 25*60*60
	secureFactory.Sign(session)
	if ValidLoginToken(session) {
		t.Fatal("expired UI sessions must be rejected")
	}
	t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", "")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ExchangeAdminPassword(configuredPassword); !ok {
		t.Fatal("INI password file must work without environment override")
	}
	common.SetConfig("admin_password_file", "")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if _, ok := ExchangeAdminPassword(configuredPassword); ok {
		t.Fatal("unconfigured deployments must remain token-only")
	}
}

func TestAdminPasswordRequiresV2AndFailsClosed(t *testing.T) {
	isolateAdminPasswordConfig(t)
	passwordFile := writeAdminFixture(t, "password", "SyntheticAdmin16")
	t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", passwordFile)
	common.SetConfig("auth_token_factor", "legacy-inline-factor")
	if err := Init(); err == nil || factory != nil || secureFactory != nil {
		t.Fatal("admin password configuration must reject legacy inline signing")
	}
	for _, mode := range []string{"none", "", "invalid"} {
		if err := ValidateAdminPasswordMode(mode); err == nil {
			t.Fatal("password configuration must reject disabled authentication")
		}
	}
	factorFile := writeAdminFixture(t, "factor", "synthetic-admin-password-factor")
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", factorFile)
	for _, test := range []struct{ name, contents string }{
		{"missing", ""}, {"empty", ""}, {"whitespace", "  \t"}, {"newline", "SyntheticPrivateValue\n"},
		{"carriage-return", "SyntheticPrivateValue\r"}, {"invalid-utf8", "SyntheticPrivateValue\xff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "password")
			if test.name != "missing" {
				if err := os.WriteFile(file, []byte(test.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", file)
			err := Init()
			if err == nil || factory != nil || secureFactory != nil || len(adminPassword) != 0 {
				t.Fatal("bad password files must not leave any active authentication factory")
			}
			if strings.Contains(err.Error(), "SyntheticPrivateValue") {
				t.Fatal("errors must not echo password contents")
			}
			if _, ok := ExchangeAdminPassword("SyntheticPrivateValue"); ok {
				t.Fatal("invalid configuration must never authenticate")
			}
		})
	}
}
