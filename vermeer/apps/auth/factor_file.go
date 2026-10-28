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
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

const minTokenSigningKeyCharacters = 16

// ReadTokenFactorFile is shared by the Master and the native token generator.
// A single terminal newline is accepted; no other whitespace is changed.
func ReadTokenFactorFile(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read token factor file: %w", err)
	}
	factor := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if err := validateTokenSigningKey(factor); err != nil {
		return "", err
	}
	return factor, nil
}

func validateTokenSigningKey(factor string) error {
	if !utf8.ValidString(factor) ||
		utf8.RuneCountInString(factor) < minTokenSigningKeyCharacters ||
		strings.TrimSpace(factor) == "" || strings.ContainsAny(factor, "\r\n") {
		return errors.New("token signing key must contain one UTF-8 line of at least 16 characters")
	}
	return nil
}
