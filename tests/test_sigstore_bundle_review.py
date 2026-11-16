import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from nmsa.sigstore_bundle_review import verify_blob


IDENTITY = "https://github.com/organization/project/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


class SigstoreOfflineTests(unittest.TestCase):
    def make_files(self, directory):
        paths = []
        for name in ("blob.bin", "bundle.sigstore.json", "trusted_root.json"):
            file = Path(directory) / name
            file.write_bytes(b"fixture-data")
            paths.append(str(file))
        return paths

    def test_missing_cosign_does_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            def missing(*args, **kwargs):
                raise FileNotFoundError("secret cannot leak")
            result = verify_blob(*paths, IDENTITY, ISSUER, runner=missing)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["signature_verified"])
            self.assertNotIn("secret", str(result))

    def test_only_fixed_offline_command_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            runner = Mock(return_value=Mock(returncode=0, stdout="private", stderr="secret"))
            result = verify_blob(*paths, IDENTITY, ISSUER, runner=runner)
            self.assertEqual(result["status"], "SIGNED_BLOB_VERIFIED")
            self.assertTrue(result["signature_verified"])
            self.assertFalse(result["image_provenance_verified"])
            self.assertFalse(result["publisher_authorized"])
            self.assertFalse(result["trusted_root_reviewed"])
            self.assertFalse(result["production_authorized"])
            self.assertNotIn("private", str(result))
            self.assertNotIn("secret", str(result))
            argv = runner.call_args.args[0]
            self.assertEqual(argv[:2], ["cosign", "verify-blob"])
            self.assertEqual(argv[argv.index("--certificate-identity")+1], IDENTITY)
            self.assertEqual(argv[argv.index("--certificate-oidc-issuer")+1], ISSUER)
            self.assertIn("--trusted-root", argv)
            self.assertIn("--offline", argv)
            self.assertFalse(runner.call_args.kwargs["shell"])

    def test_failure_never_reports_untrusted_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            runner = Mock(return_value=Mock(returncode=1, stdout="TOKEN_PRIVATE", stderr="secret"))
            result = verify_blob(*paths, IDENTITY, ISSUER, runner=runner)
            self.assertEqual(result["reason"], "bundle_verification_failed")
            self.assertNotIn("TOKEN_PRIVATE", str(result))

    def test_untrusted_signer_policy_blocks_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            for identity, issuer in (("", ISSUER), (IDENTITY, ""),
                                     (IDENTITY, "file:///issuer"),
                                     ("bad\nidentity", ISSUER)):
                runner = Mock()
                result = verify_blob(*paths, identity, issuer, runner=runner)
                self.assertEqual(result["status"], "BLOCKED")
                runner.assert_not_called()

    def test_missing_bundle_blocks_before_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            Path(paths[1]).unlink()
            runner = Mock()
            result = verify_blob(*paths, IDENTITY, ISSUER, runner=runner)
            self.assertEqual(result["status"], "BLOCKED")
            runner.assert_not_called()

    def test_oversized_bundle_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            Path(paths[1]).write_bytes(b"x"*1_000_001)
            runner = Mock()
            result = verify_blob(*paths, IDENTITY, ISSUER, runner=runner)
            self.assertEqual(result["status"], "BLOCKED")
            runner.assert_not_called()

    def test_empty_root_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            Path(paths[2]).write_bytes(b"")
            self.assertEqual(verify_blob(*paths, IDENTITY, ISSUER)["status"], "BLOCKED")

    def test_signed_blob_does_not_imply_image_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.make_files(tmp)
            result = verify_blob(*paths, IDENTITY, ISSUER,
                                 runner=Mock(return_value=Mock(returncode=0)))
            self.assertFalse(result["image_provenance_verified"])


if __name__ == "__main__":
    unittest.main()
