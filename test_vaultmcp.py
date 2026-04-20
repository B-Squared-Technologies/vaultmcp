#!/usr/bin/env python3
"""
VaultMCP test suite
Run: python3 test_vaultmcp.py
"""

import sys
import os
import json
import tempfile
import shutil
import subprocess
from pathlib import Path

# Patch vault dir to a temp location for tests
import unittest

HOOK_PATH = Path(__file__).parent / "hook.py"
CLI_PATH  = Path(__file__).parent / "vaultmcp.py"

TEST_PASS = "test-passphrase-123"

class TestEntropyDetection(unittest.TestCase):

    def setUp(self):
        # Import hook with patched vault dir
        self.tmpdir = Path(tempfile.mkdtemp())
        os.environ['VAULTMCP_KEY'] = TEST_PASS

        # Patch the vault dir in hook module
        import importlib.util
        hook_path = Path(__file__).parent / "hook.py"
        spec = importlib.util.spec_from_file_location("hook", hook_path)
        self.hook = importlib.util.module_from_spec(spec)

        # Patch vault dir before loading
        import types
        self.hook.__dict__['VAULT_DIR']  = self.tmpdir
        self.hook.__dict__['STORE_FILE'] = self.tmpdir / "store.enc"
        self.hook.__dict__['META_FILE']  = self.tmpdir / "meta.json"
        self.hook.__dict__['AUDIT_FILE'] = self.tmpdir / "audit.log"
        self.hook.__dict__['LOCK_FILE']  = self.tmpdir / ".unlocked"
        spec.loader.exec_module(self.hook)

        # Override vault paths after load
        self.hook.VAULT_DIR  = self.tmpdir
        self.hook.STORE_FILE = self.tmpdir / "store.enc"
        self.hook.AUDIT_FILE = self.tmpdir / "audit.log"
        self.hook.LOCK_FILE  = self.tmpdir / ".unlocked"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop('VAULTMCP_KEY', None)

    # --- Entropy function ---

    def test_entropy_low_for_english(self):
        # Repeated common words have low entropy
        e = self.hook.shannon_entropy("aaabbbcccdddeeefffggghhh the the the and and")
        self.assertLess(e, 3.5, "Repetitive text should have low entropy")

    def test_entropy_high_for_random(self):
        import secrets as s
        random_hex = s.token_hex(32)
        e = self.hook.shannon_entropy(random_hex)
        self.assertGreater(e, 3.5, "Random hex should have high entropy")

    def test_entropy_high_for_base64(self):
        import base64, os
        b64 = base64.b64encode(os.urandom(32)).decode()
        e = self.hook.shannon_entropy(b64)
        self.assertGreater(e, 3.5)

    # --- Known pattern detection ---

    def test_detects_aws_access_key(self):
        text = 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('aws_access_key', types)

    def test_detects_github_token(self):
        text = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('github_token', types)

    def test_detects_openai_key(self):
        text = 'OPENAI_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkL'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('openai_key', types)

    def test_detects_jwt(self):
        text = 'token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('jwt_token', types)

    def test_detects_postgres_url(self):
        text = 'DATABASE_URL=postgresql://user:supersecretpassword@db.host.com:5432/mydb'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('db_connection_string', types)

    def test_detects_private_key(self):
        text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...'
        found = self.hook.find_credentials(text)
        types = [f[1] for f in found]
        self.assertIn('private_key', types)

    def test_detects_high_entropy_unknown(self):
        # A custom internal API key with no known prefix
        text = 'MY_INTERNAL_KEY=xK9mP2qR8vL4nW6sY1tA3cE5bF7gH0jD'
        found = self.hook.find_credentials(text)
        self.assertGreater(len(found), 0, "Should detect high-entropy unknown credential")

    # --- Allowlist (should NOT flag) ---

    def test_ignores_urls(self):
        text = 'https://api.stripe.com/v1/charges'
        found = self.hook.find_credentials(text)
        self.assertEqual(len(found), 0, "URLs should not be flagged")

    def test_ignores_vault_aliases(self):
        text = 'Use [vault:MY_KEY] for this request'
        found = self.hook.find_credentials(text)
        self.assertEqual(len(found), 0, "Vault aliases should not be re-flagged")

    def test_ignores_uuid(self):
        text = 'request_id: 550e8400-e29b-41d4-a716-446655440000'
        found = self.hook.find_credentials(text)
        self.assertEqual(len(found), 0, "UUIDs should not be flagged")

    def test_ignores_short_strings(self):
        text = 'password=short'
        found = self.hook.find_credentials(text)
        self.assertEqual(len(found), 0, "Short strings below min length should not be flagged")

    # --- Crypto round-trip ---

    def test_encrypt_decrypt_roundtrip(self):
        data = {"MY_KEY": "super-secret-value", "DB_PASS": "another-secret"}
        encrypted = self.hook.encrypt_store(data, TEST_PASS)
        decrypted = self.hook.decrypt_store(encrypted, TEST_PASS)
        self.assertEqual(data, decrypted)

    def test_wrong_passphrase_fails(self):
        data = {"MY_KEY": "secret"}
        encrypted = self.hook.encrypt_store(data, TEST_PASS)
        with self.assertRaises(ValueError):
            self.hook.decrypt_store(encrypted, "wrong-passphrase")

    def test_tampered_store_fails(self):
        data = {"MY_KEY": "secret"}
        encrypted = bytearray(self.hook.encrypt_store(data, TEST_PASS))
        encrypted[50] ^= 0xFF  # Flip a byte
        with self.assertRaises(ValueError):
            self.hook.decrypt_store(bytes(encrypted), TEST_PASS)

    # --- Redaction ---

    def test_redact_replaces_value(self):
        text = 'export KEY=AKIAIOSFODNN7EXAMPLE'
        replacements = [('AKIAIOSFODNN7EXAMPLE', 'AWS_ACCESS_KEY', 11, 31)]
        result = self.hook.redact_text(text, replacements)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', result)
        self.assertIn('[vault:AWS_ACCESS_KEY]', result)

    def test_redact_multiple_values(self):
        text = 'KEY1=AKIAIOSFODNN7EXAMPLE KEY2=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'
        replacements = [
            ('AKIAIOSFODNN7EXAMPLE', 'AWS_KEY', 5, 25),
            ('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456', 'GITHUB_TOKEN', 31, 67),
        ]
        result = self.hook.redact_text(text, replacements)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', result)
        self.assertNotIn('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456', result)
        self.assertIn('[vault:AWS_KEY]', result)
        self.assertIn('[vault:GITHUB_TOKEN]', result)

    # --- Full hook flow ---

    def test_clean_payload_passes_through(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la /tmp"}
        }
        result = self.hook.process_hook(payload)
        self.assertEqual(result.get('action'), 'continue')
        self.assertNotIn('tool_input', result)  # No mutation needed

    def test_credential_in_payload_gets_vaulted(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"
            }
        }
        result = self.hook.process_hook(payload)
        self.assertEqual(result.get('action'), 'continue')
        self.assertIn('tool_input', result)
        cmd = result['tool_input']['command']
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', cmd)
        self.assertIn('[vault:', cmd)

    def test_same_value_reuses_alias(self):
        """Same credential pasted twice should get same alias"""
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"}
        }
        result1 = self.hook.process_hook(payload)
        result2 = self.hook.process_hook(payload)

        alias1 = result1['tool_input']['command'].split('[vault:')[1].split(']')[0]
        alias2 = result2['tool_input']['command'].split('[vault:')[1].split(']')[0]
        self.assertEqual(alias1, alias2, "Same value should always produce same alias")


class TestHelpers(unittest.TestCase):
    """Unit tests for utility functions that weren't covered."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        os.environ['VAULTMCP_KEY'] = TEST_PASS
        import importlib.util
        spec = importlib.util.spec_from_file_location("hook_helpers", HOOK_PATH)
        self.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hook)
        self.hook.VAULT_DIR  = self.tmpdir
        self.hook.STORE_FILE = self.tmpdir / "store.enc"
        self.hook.AUDIT_FILE = self.tmpdir / "audit.log"
        self.hook.LOCK_FILE  = self.tmpdir / ".unlocked"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop('VAULTMCP_KEY', None)

    def test_is_allowlisted_covers_known_false_positives(self):
        self.assertTrue(self.hook.is_allowlisted("https://api.example.com/foo"))
        self.assertTrue(self.hook.is_allowlisted("${SOME_VAR}"))
        self.assertTrue(self.hook.is_allowlisted("$(whoami)"))
        self.assertTrue(self.hook.is_allowlisted("[vault:MY_KEY]"))
        self.assertTrue(self.hook.is_allowlisted("<html>"))
        self.assertTrue(self.hook.is_allowlisted("connect to localhost:5432"))
        self.assertTrue(self.hook.is_allowlisted("550e8400-e29b-41d4-a716-446655440000"))
        # Real credential-looking stuff must NOT be allowlisted
        self.assertFalse(self.hook.is_allowlisted("AKIAIOSFODNN7EXAMPLE"))

    def test_alias_for_generates_collision_free_names(self):
        store = {}
        a1 = self.hook.alias_for("aws_access_key", store)
        store[a1] = "AKIA1111111111111111"
        a2 = self.hook.alias_for("aws_access_key", store)
        store[a2] = "AKIA2222222222222222"
        a3 = self.hook.alias_for("aws_access_key", store)
        self.assertEqual(a1, "AWS_ACCESS_KEY")
        self.assertEqual(a2, "AWS_ACCESS_KEY_2")
        self.assertEqual(a3, "AWS_ACCESS_KEY_3")
        self.assertEqual(len({a1, a2, a3}), 3, "aliases must be unique")

    def test_two_different_aws_keys_get_distinct_aliases(self):
        """Different credential values of the same type should NOT collide."""
        payload1 = {"tool_name": "Bash", "tool_input": {"command": "AKIAIOSFODNN7EXAMPLE"}}
        payload2 = {"tool_name": "Bash", "tool_input": {"command": "AKIA2222222222222222"}}
        r1 = self.hook.process_hook(payload1)
        r2 = self.hook.process_hook(payload2)
        a1 = r1['tool_input']['command'].split('[vault:')[1].split(']')[0]
        a2 = r2['tool_input']['command'].split('[vault:')[1].split(']')[0]
        self.assertNotEqual(a1, a2, "distinct values must get distinct aliases")


class TestLockedVaultFailOpen(unittest.TestCase):
    """When vault is locked and stdin isn't a TTY, fail open with stderr warning."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # IMPORTANT: unset VAULTMCP_KEY so the locked path triggers
        os.environ.pop('VAULTMCP_KEY', None)
        import importlib.util
        spec = importlib.util.spec_from_file_location("hook_locked", HOOK_PATH)
        self.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hook)
        self.hook.VAULT_DIR  = self.tmpdir
        self.hook.STORE_FILE = self.tmpdir / "store.enc"
        self.hook.AUDIT_FILE = self.tmpdir / "audit.log"
        self.hook.LOCK_FILE  = self.tmpdir / ".unlocked"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_locked_vault_fails_open_when_credentials_present(self):
        """Credentials detected + no passphrase source + non-TTY stdin = pass-through, no crash."""
        # sys.stdin in the test harness is typically not a TTY already; the
        # guard in process_hook short-circuits before getpass is called.
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "export KEY=AKIAIOSFODNN7EXAMPLE"}
        }
        result = self.hook.process_hook(payload)
        self.assertEqual(result.get('action'), 'continue')
        # Pass-through: no tool_input mutation because vault is locked
        self.assertNotIn('tool_input', result,
                         "locked vault must not attempt to redact")


class TestMainEntrypoint(unittest.TestCase):
    """Exercise the stdin→stdout contract the Claude Code hook runner uses."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def _run_hook(self, stdin_str, extra_env=None):
        env = os.environ.copy()
        env['HOME'] = str(self.home)
        env['VAULTMCP_KEY'] = TEST_PASS
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["python3", str(HOOK_PATH)],
            input=stdin_str,
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_main_redacts_aws_key_via_stdin(self):
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": "aws --access-key AKIAIOSFODNN7EXAMPLE"}}
        proc = self._run_hook(json.dumps(payload))
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out['action'], 'continue')
        self.assertIn('[vault:', out['tool_input']['command'])
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', out['tool_input']['command'])

    def test_main_empty_input_passes_through(self):
        proc = self._run_hook("")
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out, {"action": "continue"})

    def test_main_malformed_json_fails_open(self):
        proc = self._run_hook("not { valid json")
        self.assertEqual(proc.returncode, 0, "must exit 0 — fail open")
        out = json.loads(proc.stdout)
        self.assertEqual(out, {"action": "continue"})

    def test_main_clean_payload_passes_through(self):
        # Keep inputs short/low-entropy so nothing trips detection.
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": "ls -la /tmp"}}
        proc = self._run_hook(json.dumps(payload))
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out, {"action": "continue"})

    def test_main_locked_vault_warns_and_passes_through(self):
        """With no VAULTMCP_KEY and no .unlocked, credentials pass through with a stderr warning."""
        env = os.environ.copy()
        env['HOME'] = str(self.home)
        env.pop('VAULTMCP_KEY', None)
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": "export KEY=AKIAIOSFODNN7EXAMPLE"}}
        proc = subprocess.run(
            ["python3", str(HOOK_PATH)],
            input=json.dumps(payload),
            capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertEqual(proc.returncode, 0)
        out = json.loads(proc.stdout)
        self.assertEqual(out['action'], 'continue')
        self.assertNotIn('tool_input', out)  # no redaction attempted
        self.assertIn("locked", proc.stderr.lower())
        self.assertIn("vaultmcp", proc.stderr.lower())


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        os.environ['VAULTMCP_KEY'] = TEST_PASS

        import importlib.util
        hook_path = Path(__file__).parent / "hook.py"
        spec = importlib.util.spec_from_file_location("hook2", hook_path)
        self.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hook)
        self.hook.VAULT_DIR  = self.tmpdir
        self.hook.STORE_FILE = self.tmpdir / "store.enc"
        self.hook.AUDIT_FILE = self.tmpdir / "audit.log"
        self.hook.LOCK_FILE  = self.tmpdir / ".unlocked"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop('VAULTMCP_KEY', None)

    def test_audit_entry_written(self):
        self.hook.audit("vault", "MY_KEY", "test")
        lines = (self.tmpdir / "audit.log").read_text().strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry['action'], 'vault')
        self.assertEqual(entry['alias'], 'MY_KEY')

    def test_audit_chain_links_entries(self):
        self.hook.audit("vault", "KEY1", "test")
        self.hook.audit("vault", "KEY2", "test")
        lines = (self.tmpdir / "audit.log").read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)
        e2 = json.loads(lines[1])
        self.assertNotEqual(e2['chain'], '', "Second entry should have chain hash")


if __name__ == '__main__':
    print("\n  VaultMCP test suite\n  " + "─" * 40)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestEntropyDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestHelpers))
    suite.addTests(loader.loadTestsFromTestCase(TestLockedVaultFailOpen))
    suite.addTests(loader.loadTestsFromTestCase(TestMainEntrypoint))
    suite.addTests(loader.loadTestsFromTestCase(TestAuditLog))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
