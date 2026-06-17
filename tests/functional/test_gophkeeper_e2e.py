"""Functional black-box tests for GophKeeper server and CLI.

The suite builds real binaries, starts a real gRPC server, and drives the
system only through the CLI. PostgreSQL is required and is expected at
GOPHKEEPER_FUNC_DATABASE_URL or the docker-compose default URL.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_URL = "postgres://user:pass@127.0.0.1:5432/gophkeeper?sslmode=disable"
JWT_SECRET = "functional-test-secret-functional-test-32-bytes"
ITEM_ID_RE = re.compile(r"item\s+([0-9a-fA-F-]{36})\s+revision=(\d+)")


class CommandResultError(AssertionError):
    """Reports an unexpected command exit in functional tests."""


class GophKeeperFunctionalTest(unittest.TestCase):
    """End-to-end tests for the GophKeeper server and CLI binaries."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.database_url = os.environ.get("GOPHKEEPER_FUNC_DATABASE_URL", DEFAULT_DATABASE_URL)
        cls.tempdir = tempfile.TemporaryDirectory(prefix="gophkeeper-func-")
        cls.workdir = Path(cls.tempdir.name)
        cls.server_bin = cls.workdir / "gophkeeper-server"
        cls.client_bin = cls.workdir / "gophkeeper-client"
        try:
            cls.server_addr = f"127.0.0.1:{free_tcp_port()}"
        except OSError as exc:
            cls.cleanup_class()
            raise unittest.SkipTest(f"local TCP sockets are not available: {exc}") from exc
        cls.server_log = open(cls.workdir / "server.log", "w+", encoding="utf-8")
        cls.server: subprocess.Popen[str] | None = None

        try:
            cls.build_binaries()
            cls.start_server()
        except unittest.SkipTest:
            cls.cleanup_class()
            raise
        except Exception:
            cls.cleanup_class()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.cleanup_class()

    @classmethod
    def cleanup_class(cls) -> None:
        server = getattr(cls, "server", None)
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        log = getattr(cls, "server_log", None)
        if log is not None and not log.closed:
            log.close()
        tempdir = getattr(cls, "tempdir", None)
        if tempdir is not None:
            tempdir.cleanup()

    @classmethod
    def build_binaries(cls) -> None:
        env = os.environ.copy()
        env.setdefault("GOCACHE", str(cls.workdir / "go-cache"))
        build_specs = (
            (cls.server_bin, "./cmd/gophkeeper-server"),
            (cls.client_bin, "./cmd/gophkeeper-client"),
        )
        for output, package in build_specs:
            result = subprocess.run(
                ["go", "build", "-o", str(output), package],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
            if result.returncode != 0:
                raise CommandResultError(
                    f"go build {package} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                )

    @classmethod
    def start_server(cls) -> None:
        env = os.environ.copy()
        env.update(
            {
                "GOPHKEEPER_DATABASE_URL": cls.database_url,
                "GOPHKEEPER_JWT_SECRET": JWT_SECRET,
                "GOPHKEEPER_LISTEN_ADDR": cls.server_addr,
            }
        )
        cls.server = subprocess.Popen(
            [str(cls.server_bin), "--listen", cls.server_addr],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=cls.server_log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if cls.server.poll() is not None:
                cls.server_log.seek(0)
                log = cls.server_log.read()
                raise unittest.SkipTest(
                    "functional PostgreSQL is not available or server failed to start:\n" + log
                )
            if tcp_connects(cls.server_addr):
                return
            time.sleep(0.1)
        cls.server_log.seek(0)
        log = cls.server_log.read()
        raise TimeoutError("server did not start listening in time:\n" + log)

    def make_cache(self, name: str) -> Path:
        return self.workdir / f"{name}-{uuid.uuid4().hex}.db"

    def run_client(
        self,
        cache: Path,
        *args: str,
        expect_ok: bool = True,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                str(self.client_bin),
                "--server",
                self.server_addr,
                "--cache",
                str(cache),
                *args,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if expect_ok and result.returncode != 0:
            raise CommandResultError(
                f"client {' '.join(args)} failed with code {result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        if not expect_ok and result.returncode == 0:
            raise CommandResultError(
                f"client {' '.join(args)} unexpectedly succeeded\nstdout:\n{result.stdout}"
            )
        return result

    def register(self, cache: Path, login: str, password: str) -> None:
        result = self.run_client(cache, "register", "--login", login, "--password", password)
        self.assertIn("registered user", command_output(result))

    def login(
        self,
        cache: Path,
        login: str,
        password: str,
        expect_ok: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_client(cache, "login", "--login", login, "--password", password, expect_ok=expect_ok)

    def add_item(self, cache: Path, password: str, *args: str) -> tuple[str, int]:
        result = self.run_client(cache, "add", "--password", password, *args)
        return parse_item_header(command_output(result))

    def get_item(self, cache: Path, item_id: str, password: str, *, offline: bool = False) -> dict:
        args = ["get", item_id, "--password", password]
        if offline:
            args.append("--offline")
        result = self.run_client(cache, *args)
        return json.loads(command_output(result))

    def test_version_command_does_not_require_server_state(self) -> None:
        cache = self.make_cache("version")
        result = self.run_client(cache, "version")
        self.assertRegex(command_output(result), r"version=.+ build_date=.+")

    def test_full_secret_lifecycle_sync_conflict_and_offline_read(self) -> None:
        login = f"alice-{uuid.uuid4().hex[:12]}"
        password = "password-1"
        cache_primary = self.make_cache("primary")
        cache_secondary = self.make_cache("secondary")

        self.register(cache_primary, login, password)

        login_item_id, revision = self.add_item(
            cache_primary,
            password,
            "--type",
            "login_password",
            "--name",
            "github",
            "--metadata",
            "site=github.com",
            "--metadata",
            "owner=alice",
            "--username",
            "alice",
            "--secret",
            "initial-secret",
        )
        self.assertEqual(revision, 1)

        text_item_id, _ = self.add_item(
            cache_primary,
            password,
            "--type",
            "text",
            "--name",
            "note",
            "--metadata",
            "kind=note",
            "--text",
            "private note text",
        )

        binary_file = self.workdir / "payload.bin"
        binary_file.write_bytes(b"\x00\x01binary secret\xff")
        binary_item_id, _ = self.add_item(
            cache_primary,
            password,
            "--type",
            "binary",
            "--name",
            "binary-file",
            "--file",
            str(binary_file),
        )

        card_item_id, _ = self.add_item(
            cache_primary,
            password,
            "--type",
            "card",
            "--name",
            "main-card",
            "--metadata",
            "bank=testbank",
            "--card-number",
            "4111111111111111",
            "--card-holder",
            "ALICE TEST",
            "--card-expiry",
            "12/30",
            "--card-cvv",
            "123",
        )

        listed = command_output(self.run_client(cache_primary, "list", "--password", password))
        self.assertIn("login_password\tgithub", listed)
        self.assertIn("text\tnote", listed)
        self.assertIn("binary\tbinary-file", listed)
        self.assertIn("card\tmain-card", listed)

        login_payload = self.get_item(cache_primary, login_item_id, password)
        self.assertEqual(login_payload["type"], "login_password")
        self.assertEqual(login_payload["metadata"]["site"], "github.com")
        self.assertEqual(login_payload["data"]["login"], "alice")
        self.assertEqual(login_payload["data"]["password"], "initial-secret")

        text_payload = self.get_item(cache_primary, text_item_id, password)
        self.assertEqual(text_payload["data"]["text"], "private note text")
        binary_payload = self.get_item(cache_primary, binary_item_id, password)
        self.assertEqual(binary_payload["type"], "binary")
        card_payload = self.get_item(cache_primary, card_item_id, password)
        self.assertEqual(card_payload["data"]["number"], "4111111111111111")

        updated = self.run_client(
            cache_primary,
            "update",
            login_item_id,
            "--password",
            password,
            "--revision",
            "1",
            "--type",
            "login_password",
            "--name",
            "github-updated",
            "--username",
            "alice-new",
            "--secret",
            "updated-secret",
        )
        updated_id, updated_revision = parse_item_header(command_output(updated))
        self.assertEqual(updated_id, login_item_id)
        self.assertEqual(updated_revision, 2)

        stale_update = self.run_client(
            cache_primary,
            "update",
            login_item_id,
            "--password",
            password,
            "--revision",
            "1",
            "--type",
            "login_password",
            "--name",
            "stale",
            "--username",
            "stale",
            "--secret",
            "stale-secret",
            expect_ok=False,
        )
        self.assertIn("Aborted", stale_update.stderr + stale_update.stdout)

        self.login(cache_secondary, login, password)
        sync_result = self.run_client(cache_secondary, "sync")
        self.assertRegex(command_output(sync_result), r"synced [1-9]\d* changes")
        secondary_list = command_output(self.run_client(cache_secondary, "list", "--password", password, "--offline"))
        self.assertIn("login_password\tgithub-updated", secondary_list)
        self.assertIn("card\tmain-card", secondary_list)

        offline_payload = self.get_item(cache_secondary, login_item_id, password, offline=True)
        self.assertEqual(offline_payload["data"]["password"], "updated-secret")

        delete_result = self.run_client(cache_primary, "delete", text_item_id, "--revision", "1")
        deleted_id, deleted_revision = parse_item_header(command_output(delete_result))
        self.assertEqual(deleted_id, text_item_id)
        self.assertEqual(deleted_revision, 2)

        self.run_client(cache_secondary, "sync")
        deleted_list = command_output(
            self.run_client(
                cache_secondary,
                "list",
                "--password",
                password,
                "--offline",
                "--include-deleted",
            )
        )
        self.assertIn(f"{text_item_id}\tdeleted", deleted_list)

        cache_bytes = cache_secondary.read_bytes()
        for plaintext in (b"updated-secret", b"private note text", b"4111111111111111", b"binary secret"):
            self.assertNotIn(plaintext, cache_bytes)

    def test_authorization_isolation_between_users(self) -> None:
        owner_login = f"owner-{uuid.uuid4().hex[:12]}"
        intruder_login = f"intruder-{uuid.uuid4().hex[:12]}"
        password = "password-1"
        owner_cache = self.make_cache("owner")
        intruder_cache = self.make_cache("intruder")

        self.register(owner_cache, owner_login, password)
        owner_item_id, _ = self.add_item(
            owner_cache,
            password,
            "--type",
            "text",
            "--name",
            "owner-note",
            "--text",
            "owner-only-secret",
        )

        self.register(intruder_cache, intruder_login, password)
        denied = self.run_client(
            intruder_cache,
            "get",
            owner_item_id,
            "--password",
            password,
            expect_ok=False,
        )
        self.assertIn("NotFound", denied.stderr + denied.stdout)

        intruder_list = command_output(self.run_client(intruder_cache, "list", "--password", password))
        self.assertNotIn(owner_item_id, intruder_list)
        self.assertNotIn("owner-note", intruder_list)

        wrong_password = self.login(self.make_cache("wrong-password"), owner_login, "wrong-password", expect_ok=False)
        self.assertIn("Unauthenticated", wrong_password.stderr + wrong_password.stdout)


def parse_item_header(output: str) -> tuple[str, int]:
    match = ITEM_ID_RE.search(output)
    if not match:
        raise AssertionError(f"could not parse item header from output: {output!r}")
    return match.group(1), int(match.group(2))


def command_output(result: subprocess.CompletedProcess[str]) -> str:
    """Returns user-visible command output regardless of stream choice."""
    return result.stdout + result.stderr


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def tcp_connects(addr: str) -> bool:
    host, port = addr.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=0.2):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    if shutil.which("go") is None:
        raise SystemExit("go binary is required")
    unittest.main(verbosity=2)
