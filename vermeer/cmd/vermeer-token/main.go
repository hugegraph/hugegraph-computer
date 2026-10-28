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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"vermeer/apps/auth"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vermeer-token", flag.ContinueOnError)
	flags.SetOutput(stderr)
	user := flags.String("user", "foo", "user name")
	space := flags.String("space", "bar", "space name")
	factorFile := flags.String("factor-file", "", "read the token factor from this file")
	outputFile := flags.String("output-file", "", "write only the token to this file with mode 0600")
	quiet := flags.Bool("quiet", false, "print only the token when -output-file is not set")
	client := flags.String("client", "hg", "client identifier")
	immortal := flags.Bool("i", false, "immortal token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *user == "" {
		return errors.New("user must not be empty")
	}
	if *factorFile == "" {
		return errors.New("-factor-file is required for deployment tokens")
	}
	signingKey, err := auth.ReadTokenFactorFile(*factorFile)
	if err != nil {
		return err
	}
	secureFactory, err := auth.NewSecureTokenFactory(signingKey)
	if err != nil {
		return err
	}
	tokenObj := secureFactory.NewToken(*user, *space, *client)
	if *immortal {
		tokenObj.Time = math.MaxInt64
	}
	secureFactory.Sign(tokenObj)
	data, err := json.Marshal(tokenObj)
	if err != nil {
		return errors.New("encode token")
	}
	token := auth.ToBase58(string(data))
	if *outputFile != "" {
		return writeTokenFile(*outputFile, token)
	}
	if *quiet {
		_, err = fmt.Fprintln(stdout, token)
		return err
	}
	_, err = fmt.Fprintf(stdout, "    user: %s\n   space: %s\n  client: %s\nimmortal: %t\n   token: %s\n",
		*user, *space, *client, *immortal, token)
	return err
}

func writeTokenFile(path, token string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".vermeer-token-*")
	if err != nil {
		return fmt.Errorf("create token output: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(token + "\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("write token output: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close token output: %w", err)
	}
	// Rename publishes a complete 0600 file and never follows a destination symlink.
	if err = os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("publish token output: %w", err)
	}
	return nil
}
