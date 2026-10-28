#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Check the real runtime image without PD/Store or externally exposed ports."""

import argparse
import hashlib
import hmac
import http.cookiejar
import http.cookies
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


class SmokeFailure(Exception):
    """A diagnostic that never includes credential values or raw service output."""


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def docker(arguments, timeout=30, success=True):
    try:
        result = subprocess.run(
            ["docker", *arguments], capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure("Docker operation exceeded its bounded timeout") from error
    if success and result.returncode != 0:
        raise SmokeFailure("Docker operation failed; inspect the candidate image locally")
    return result


def write_private(path, contents):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(contents)


def decode_token(encoded, factor):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    try:
        for character in encoded:
            number = number * 58 + alphabet.index(character)
        raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
        token = json.loads(raw)
        payload = [token["u"], token["s"], token["n"], token["c"], token["t"]]
        source = b"vermeer-token-v2\x00" + json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode()
        expected = "v2:" + hmac.new(factor.encode(), source, hashlib.sha256).hexdigest()
        require(hmac.compare_digest(token["d"], expected), "runtime token has an invalid v2 signature")
        return token
    except (ValueError, KeyError, TypeError) as error:
        raise SmokeFailure("runtime token is not a valid opaque v2 credential") from error


def opener(cookie_jar=None):
    # The only HTTP destination is the Docker port bound to local loopback.
    handlers = [urllib.request.ProxyHandler({})]
    if cookie_jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))
    return urllib.request.build_opener(*handlers)


def request(client, base, path, body=None, bearer=None):
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    try:
        response = client.open(urllib.request.Request(base + path, data=body, headers=headers), timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(2 * 1024 * 1024)


def check_image(image):
    containers = []
    prefix = "vermeer-image-smoke-" + uuid.uuid4().hex[:12]

    def run(arguments, *, name, timeout=30, success=True):
        container_name = prefix + "-" + name
        containers.append(container_name)
        try:
            return docker(["run", "--name", container_name, "--rm", *arguments], timeout, success)
        except SmokeFailure as error:
            raise SmokeFailure("runtime image " + name + " check failed: " + str(error)) from error

    try:
        if docker(["image", "inspect", image], success=False).returncode != 0:
            docker(["pull", image], timeout=180)
        modes = run(
            ["--entrypoint", "stat", image, "-c", "%a", "/go/bin/app", "/go/bin/vermeer-token"],
            name="modes",
        ).stdout.splitlines()
        require(modes == [b"755", b"755"], "runtime app and helper must both be executable mode 0755")
        nonroot = run(
            [
                "--user", "100:101", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                "--entrypoint", "/bin/sh", image, "-ec",
                """umask 077
work=$(mktemp -d /tmp/vermeer-token.XXXXXX)
trap 'rm -rf "$work"' EXIT
printf '%s' synthetic-nonroot-runtime-factor > "$work/factor"
/go/bin/vermeer-token -factor-file "$work/factor" -output-file "$work/token" \
  -user admin -space '$DEFAULT' -client runtime-smoke -i -quiet > "$work/out" 2> "$work/err"
test ! -s "$work/out"
test ! -s "$work/err"
test "$(stat -c %a "$work/token")" = 600
cat "$work/token"
""",
            ],
            name="nonroot",
        )
        nonroot_token = decode_token(nonroot.stdout.decode().strip(), "synthetic-nonroot-runtime-factor")
        require(nonroot_token["t"] == 2**63 - 1, "helper must support long-lived v2 service tokens")
        rejected = run(
            ["--entrypoint", "/go/bin/vermeer-token", image, "-factor", "synthetic-legacy-factor", "-quiet"],
            name="legacy-flag", success=False,
        )
        require(rejected.returncode != 0 and not rejected.stdout and
                b"flag provided but not defined: -factor" in rejected.stderr,
                "runtime helper must reject legacy inline factors")
        missing = run(
            ["--entrypoint", "/go/bin/vermeer-token", image, "-factor-file", "/missing-factor", "-quiet"],
            name="missing-factor", success=False,
        )
        require(missing.returncode != 0 and not missing.stdout and b"read token factor file" in missing.stderr,
                "helper must fail closed for a missing factor file")

        with tempfile.TemporaryDirectory(prefix="vermeer-runtime-smoke-") as directory:
            private = Path(directory)
            factor = secrets.token_hex(32)
            password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            write_private(private / "factor", factor.encode())
            write_private(private / "password", password.encode())
            write_private(private / "empty-password", b"")
            mount = ["-v", f"{private}:/probe:ro"]
            for label, environment, arguments in [
                ("master-factor", ["VERMEER_AUTH_TOKEN_FACTOR_FILE=/missing-factor"], ["-auth=token"]),
                ("master-password", ["VERMEER_AUTH_TOKEN_FACTOR_FILE=/probe/factor",
                                     "VERMEER_ADMIN_PASSWORD_FILE=/missing-password"], ["-auth=token"]),
                ("master-empty", ["VERMEER_AUTH_TOKEN_FACTOR_FILE=/probe/factor",
                                  "VERMEER_ADMIN_PASSWORD_FILE=/probe/empty-password"], ["-auth=token"]),
                ("master-none", ["VERMEER_ADMIN_PASSWORD_FILE=/probe/password"], ["-auth=none"]),
            ]:
                environment_args = [item for value in environment for item in ("-e", value)]
                failed = run([*mount, *environment_args, image, "-env=master", *arguments],
                             name=label, timeout=15, success=False)
                observed = failed.stdout + failed.stderr
                require(failed.returncode != 0 and b"token authentication initialization failed" in observed,
                        "Master must reject invalid deployment credentials before listening: " + label)
                require(factor.encode() not in observed and password.encode() not in observed,
                        "startup errors must not expose credentials")
            service = run(
                [*mount, "--entrypoint", "/go/bin/vermeer-token", image,
                 "-factor-file", "/probe/factor", "-user", "admin", "-space", "$DEFAULT",
                 "-client", "runtime-smoke", "-i", "-quiet"], name="service-token",
            ).stdout.decode().strip()
            decode_token(service, factor)
            master_name = prefix + "-master"
            containers.append(master_name)
            docker([
                "run", "--rm", "-d", "--name", master_name,
                "-p", "127.0.0.1::6688", *mount,
                "-e", "VERMEER_AUTH_TOKEN_FACTOR_FILE=/probe/factor",
                "-e", "VERMEER_ADMIN_PASSWORD_FILE=/probe/password",
                image, "-env=master", "-auth=token",
            ])
            address = docker(["port", master_name, "6688/tcp"]).stdout.decode().strip()
            require(address.startswith("127.0.0.1:"), "smoke Master must bind only local loopback")
            base = "http://" + address
            anonymous = opener()
            deadline = time.monotonic() + 45
            while True:
                try:
                    if request(anonymous, base, "/api/v1/healthcheck")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                require(time.monotonic() < deadline, "smoke Master did not become healthy within 45 seconds")
                time.sleep(0.2)
            status, _, html = request(anonymous, base, "/")
            require(status == 200 and b"Admin password or token" in html and b'id="admin_token"' in html,
                    "production image must embed the short-credential login UI")
            for path in ("/api/v1/master", "/api/v1/workers"):
                require(request(anonymous, base, path)[0] == 401, "native metadata must reject anonymous requests")
                require(request(anonymous, base, path, bearer=password)[0] == 401,
                        "short UI password must not act as an API Bearer token")
                require(request(anonymous, base, path, bearer=service)[0] == 200,
                        "long-lived v2 service token must retain API access")
            wrong = "x" * 16 if password != "x" * 16 else "y" * 16
            bad_status, bad_headers, bad_body = request(anonymous, base, "/api/v1/login", {"token": wrong})
            require(bad_status == 401 and not bad_headers.get("Set-Cookie"),
                    "incorrect administrator password must not issue a session")
            session_client = opener(http.cookiejar.CookieJar())
            status, headers, body = request(session_client, base, "/api/v1/login", {"token": password})
            cookie = http.cookies.SimpleCookie()
            cookie.load(headers.get("Set-Cookie", ""))
            require(status == 200 and "vat" in cookie and cookie["vat"]["httponly"] and
                    cookie["vat"]["max-age"] == "86400", "password login must issue an HttpOnly 24-hour cookie")
            cookie_value = cookie["vat"].value
            session = decode_token(cookie_value, factor)
            require(session["u"] == "admin" and session["s"] == "$DEFAULT" and
                    abs(time.time() - session["t"]) < 10, "UI session must carry the current admin identity")
            for path in ("/api/v1/master", "/api/v1/workers"):
                require(request(session_client, base, path)[0] == 200, "native UI session must authorize metadata")
            require(request(anonymous, base, "/api/v1/login", {"token": service})[0] == 200,
                    "long opaque token login must remain supported")
            observed_logs = docker(["logs", master_name])
            logs = observed_logs.stdout + observed_logs.stderr
            for sensitive in (factor, password, service, cookie_value):
                require(sensitive.encode() not in logs + body + bad_body,
                        "service output must not expose credentials or raw cookies")
    finally:
        if containers:
            docker(["rm", "-f", *containers], timeout=15, success=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="locally built image tag or published image URL/digest")
    arguments = parser.parse_args()
    require(arguments.image and not arguments.image.startswith("-"), "an image reference is required")
    check_image(arguments.image)
    print("runtime image smoke passed: executable helpers, v2 tokens, fail-closed startup and authenticated UI")


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as error:
        print("runtime image smoke failed: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print("runtime image smoke failed with " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
