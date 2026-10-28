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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const secureTokenPrefix = "v2:"

// SecureTokenFactory keeps deployment signing keys out of the legacy token implementation.
// Its concrete type has no legacy Factor field or SHA1 signing path.
type SecureTokenFactory struct {
	signingKey []byte
}

// NewSecureTokenFactory uses versioned HMAC-SHA256 tokens without legacy fallback.
func NewSecureTokenFactory(signingKey string) (*SecureTokenFactory, error) {
	if err := validateTokenSigningKey(signingKey); err != nil {
		return nil, err
	}
	return &SecureTokenFactory{signingKey: []byte(signingKey)}, nil
}

func (factory *SecureTokenFactory) NewToken(user, space, client string) *Token {
	return newToken(user, space, client)
}

func (factory *SecureTokenFactory) Sign(token *Token) {
	if token == nil {
		return
	}
	if len(factory.signingKey) == 0 {
		token.Digest = ""
		return
	}
	token.Digest = secureTokenPrefix + hex.EncodeToString(factory.signature(token))
}

func (factory *SecureTokenFactory) Verify(token *Token) bool {
	if token == nil || len(factory.signingKey) == 0 {
		return false
	}
	encoded, ok := strings.CutPrefix(token.Digest, secureTokenPrefix)
	if !ok || len(encoded) != sha256.Size*2 {
		return false
	}
	signature, err := hex.DecodeString(encoded)
	return err == nil && hmac.Equal(signature, factory.signature(token))
}

func (factory *SecureTokenFactory) signature(token *Token) []byte {
	// Fixed-field JSON preserves field boundaries and excludes the digest.
	// Authenticate the nickname as well as every authorization field.
	payload, _ := json.Marshal([5]interface{}{token.User, token.Space, token.Nick, token.Client, token.Time})
	mac := hmac.New(sha256.New, factory.signingKey)
	_, _ = mac.Write([]byte("vermeer-token-v2\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
