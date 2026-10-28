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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
	"vermeer/apps/common"
	"vermeer/apps/structure"
)

// AdminSessionMaxAge is the lifetime of a native UI password session in seconds.
const AdminSessionMaxAge = tokenMaxAge

var adminPassword []byte

func adminPasswordFile() string {
	if file := os.Getenv("VERMEER_ADMIN_PASSWORD_FILE"); file != "" {
		return file
	}
	file, _ := common.GetConfigDefault("admin_password_file", "").(string)
	return file
}

// ValidateAdminPasswordMode rejects a configured UI password when authentication is disabled.
func ValidateAdminPasswordMode(authType string) error {
	if adminPasswordFile() != "" && authType != "token" {
		return errors.New("admin password file requires file-backed v2 token authentication")
	}
	return nil
}

func readAdminPasswordFile(file string) ([]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read admin password file: %w", err)
	}
	if len(data) == 0 || !utf8.Valid(data) || strings.ContainsAny(string(data), "\r\n") ||
		strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("admin password file must contain a nonempty single-line UTF-8 credential")
	}
	return data, nil
}

// ExchangeAdminPassword authenticates the UI credential without exposing it as a Bearer token.
// The resulting session is an ordinary expiring v2 administrator token.
func ExchangeAdminPassword(credential string) (string, bool) {
	if secureFactory == nil || len(adminPassword) == 0 ||
		subtle.ConstantTimeCompare([]byte(credential), adminPassword) != 1 {
		return "", false
	}
	token := secureFactory.NewToken(structure.AdminName, structure.DefaultSpaceName, "native-ui")
	secureFactory.Sign(token)
	data, err := json.Marshal(token)
	if err != nil {
		return "", false
	}
	return ToBase58(string(data)), true
}

func validSignature(token *Token) bool {
	if secureFactory != nil {
		return secureFactory.Verify(token)
	}
	return factory != nil && factory.Verify(token)
}

// ValidLoginToken validates opaque token login before a session cookie is set.
func ValidLoginToken(token *Token) bool {
	if token == nil || !validSignature(token) || tokenExpired(token) {
		return false
	}
	_, err := structure.NewCredential(token.User, token.Space)
	return err == nil
}
