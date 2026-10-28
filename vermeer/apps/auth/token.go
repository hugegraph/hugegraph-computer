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
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

var empty = ""

const (
	defaultFactor     = "!^_^!YouCanTypeWhateverYouWant"
	secureTokenPrefix = "v2:"
)

type Token struct {
	User   string `json:"u"` // Login ID
	Space  string `json:"s"` // Graph space
	Nick   string `json:"n"` // [Nickname]
	Digest string `json:"d"` // Digest
	Client string `json:"c"` //	Identifier of invoker, e.g. IP address, SN of device.
	Time   int64  `json:"t"` // Note: time in seconds form not milliseconds
}

type TokenFactory struct {
	Factor  string
	randoms *[4]string
	// File-backed deployment keys never populate the legacy Factor field.
	signingKey []byte
}

// NewSecureTokenFactory uses versioned HMAC-SHA256 tokens without legacy fallback.
func NewSecureTokenFactory(signingKey string) (*TokenFactory, error) {
	if err := validateTokenSigningKey(signingKey); err != nil {
		return nil, err
	}
	return &TokenFactory{signingKey: []byte(signingKey)}, nil
}

func (factory *TokenFactory) getRandoms() *[4]string {
	if factory.randoms == nil {
		if factory.Factor == "" {
			factory.Factor = defaultFactor
		}

		if len(factory.Factor) < 4 {
			factory.Factor = factory.Factor + defaultFactor
		}

		buf := []rune(factory.Factor)
		var r [4]string
		l := len(buf) / 4

		for i := 0; i < 4; i++ {
			r[i] = string(buf[i*l : (i+1)*l])
		}

		factory.randoms = &r
	}
	return factory.randoms
}

// NewToken Create a Token by login-id, space, client(e.g. IP address).
func (factory *TokenFactory) NewToken(user string, space string, client string) *Token {
	if user == "" {
		return nil
	}
	if client == "" {
		client = empty
	}
	return &Token{User: user, Space: space, Client: client, Time: time.Now().Unix()}
}

func (factory *TokenFactory) Sign(a *Token) {
	if a == nil {
		return
	}
	if factory.signingKey != nil {
		a.Digest = secureTokenPrefix + hex.EncodeToString(factory.secureSignature(a))
		return
	}
	a.Digest = digest(factory.signSource(a))
}

func (factory *TokenFactory) Verify(a *Token) bool {
	if a == nil {
		return false
	}

	if factory.signingKey != nil {
		encoded, ok := strings.CutPrefix(a.Digest, secureTokenPrefix)
		if !ok || len(encoded) != sha256.Size*2 {
			return false
		}
		signature, err := hex.DecodeString(encoded)
		return err == nil && hmac.Equal(signature, factory.secureSignature(a))
	}
	s := digest(factory.signSource(a))

	return hmac.Equal([]byte(a.Digest), []byte(s))
}

func (factory *TokenFactory) secureSignature(token *Token) []byte {
	// Fixed-field JSON preserves field boundaries and excludes the digest.
	// Authenticate the nickname as well as every authorization field.
	payload, _ := json.Marshal([5]interface{}{token.User, token.Space, token.Nick, token.Client, token.Time})
	mac := hmac.New(sha256.New, factory.signingKey)
	_, _ = mac.Write([]byte("vermeer-token-v2\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func digest(s string) string {
	if s == "" {
		return ""
	}
	h := sha1.New()
	_, _ = io.WriteString(h, s)
	return hex.EncodeToString(h.Sum(nil))
}

func (factory *TokenFactory) signSource(a *Token) string {
	var sb strings.Builder
	sb.WriteString(factory.getRandoms()[0])
	sb.WriteString(a.User)
	sb.WriteString(factory.getRandoms()[1])
	sb.WriteString(a.Space)
	sb.WriteString(factory.getRandoms()[2])
	sb.WriteString(strconv.FormatInt(a.Time, 10))
	sb.WriteString(factory.getRandoms()[3])
	sb.WriteString(a.Client)
	res := sb.String()
	return res
}
