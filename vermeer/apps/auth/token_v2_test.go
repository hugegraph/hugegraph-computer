/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. The ASF
licenses this file to You under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
*/

package auth

import (
	"math"
	"strings"
	"testing"
)

func TestSecureTokenProtocolAndLegacyCompatibility(t *testing.T) {
	const key = "legacy-compatibility-factor"
	legacy := &TokenFactory{Factor: key}
	secure, err := NewSecureTokenFactory(key)
	if err != nil {
		t.Fatal(err)
	}
	if secure.signingKey == nil {
		t.Fatal("secure keys must be separate from legacy factor state")
	}
	token := &Token{User: "admin", Space: "$DEFAULT", Client: "compatibility", Time: math.MaxInt64}
	legacy.Sign(token)
	if token.Digest != "a89528d7bfec6d12addab5a403da64a148f03ce5" || !legacy.Verify(token) {
		t.Fatal("legacy inline signing must preserve the historical protocol")
	}
	if secure.Verify(token) {
		t.Fatal("file-backed factories must not accept legacy signatures")
	}
	secure.Sign(token)
	// Independent HMAC-SHA256 fixture over the documented domain and JSON payload.
	const expected = "v2:f567b23ada3378d0b216008b2076afd3577b2e69be49dab6efcaeb2618d338eb"
	if token.Digest != expected || !secure.Verify(token) {
		t.Fatal("unexpected v2 signing protocol")
	}
	if legacy.Verify(token) {
		t.Fatal("legacy factories must not accept v2 signatures")
	}
	rotated, err := NewSecureTokenFactory("rotated-deployment-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Verify(token) {
		t.Fatal("rotating the signing key must invalidate old signatures")
	}
	if secure.Verify(nil) || legacy.Verify(nil) {
		t.Fatal("nil tokens must be rejected")
	}
}

func TestSecureTokenRejectsTampering(t *testing.T) {
	factory, err := NewSecureTokenFactory("synthetic-secure-signing-key")
	if err != nil {
		t.Fatal(err)
	}
	original := factory.NewToken("admin", "$DEFAULT", "hubble")
	original.Nick = "display-name"
	original.Time = math.MaxInt64
	factory.Sign(original)
	mutations := map[string]func(*Token){
		"user":        func(token *Token) { token.User = "another-user" },
		"space":       func(token *Token) { token.Space = "another-space" },
		"nickname":    func(token *Token) { token.Nick = "another-name" },
		"client":      func(token *Token) { token.Client = "another-client" },
		"time":        func(token *Token) { token.Time-- },
		"version":     func(token *Token) { token.Digest = "v1:" + strings.TrimPrefix(token.Digest, "v2:") },
		"unversioned": func(token *Token) { token.Digest = strings.TrimPrefix(token.Digest, "v2:") },
		"truncated":   func(token *Token) { token.Digest = token.Digest[:len(token.Digest)-1] },
		"invalid-hex": func(token *Token) { token.Digest = "v2:" + strings.Repeat("z", 64) },
		"signature":   func(token *Token) { token.Digest = "v2:" + strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			token := *original
			mutate(&token)
			if factory.Verify(&token) {
				t.Fatal("modified token must not authenticate")
			}
		})
	}
	first := &Token{User: "a", Space: "bc", Client: "client", Time: 1}
	second := &Token{User: "ab", Space: "c", Client: "client", Time: 1}
	factory.Sign(first)
	second.Digest = first.Digest
	if factory.Verify(second) {
		t.Fatal("signed fields must retain unambiguous boundaries")
	}
}

func TestSecureTokenFactoryRejectsInvalidKeys(t *testing.T) {
	for _, key := range []string{"", "abc", "密碼", "    ", "key\nsecond-line", "key\xff"} {
		factory, err := NewSecureTokenFactory(key)
		if err == nil || factory != nil {
			t.Fatal("invalid secure keys must not create a legacy factory")
		}
	}
}

func TestZeroValueSecureTokenFactoryFailsClosed(t *testing.T) {
	var factory SecureTokenFactory
	token := &Token{User: "admin", Space: "$DEFAULT", Client: "zero-value", Time: math.MaxInt64}
	token.Digest = secureTokenPrefix + strings.Repeat("0", 64)
	if factory.Verify(token) {
		t.Fatal("zero-value factory must never authenticate a token")
	}
	factory.Sign(token)
	if token.Digest != "" || factory.Verify(token) {
		t.Fatal("zero-value signing must clear the signature and remain unusable")
	}
}
