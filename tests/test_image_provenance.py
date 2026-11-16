import json
import unittest
from unittest.mock import Mock
from nmsa.image_provenance import TEMPLATE, inspect, interpret

IMAGE = "sha256:" + "a" * 64
REGISTRY = "registry.example.invalid/example@sha256:" + "b" * 64

class ImageProvenanceTests(unittest.TestCase):
    def test_image_id_without_registry_digest_is_not_provenance(self):
        r=interpret(IMAGE+"|null|linux|amd64", IMAGE)
        self.assertEqual(r["status"], "LOCAL_IMAGE_IDENTIFIED")
        self.assertFalse(r["registry_digest_present"])
        self.assertFalse(r["image_provenance_verified"])
        self.assertFalse(r["signature_verified"])
        self.assertFalse(r["independent_review_completed"])

    def test_registry_digest_present_is_not_signature(self):
        r=interpret(IMAGE+"|"+json.dumps([REGISTRY])+"|linux|arm64", IMAGE)
        self.assertTrue(r["registry_digest_present"])
        self.assertEqual(r["registry_digest_count"],1)
        self.assertFalse(r["signature_verified"])
        self.assertNotIn("registry.example", str(r))

    def test_wrong_id_or_os_fails_closed(self):
        self.assertEqual(interpret("sha256:"+"b"*64+"|[]|linux|amd64", IMAGE)["status"],"BLOCKED")
        self.assertEqual(interpret(IMAGE+"|[]|windows|amd64", IMAGE)["status"],"BLOCKED")

    def test_bad_metadata_and_oversize_block(self):
        for x in ("garbage", IMAGE+"|{}|linux|amd64", "A"*9000,
                  IMAGE+'|["unsafe|sha256:bad"]|linux|amd64'):
            self.assertEqual(interpret(x, IMAGE)["status"],"BLOCKED")

    def test_invalid_image_id_never_runs_docker(self):
        runner=Mock()
        r=inspect("node:latest", runner=runner)
        self.assertEqual(r["status"], "BLOCKED")
        runner.assert_not_called()

    def test_only_inspection_command_runs(self):
        result=Mock(returncode=0,stdout=IMAGE+"|[]|linux|amd64")
        runner=Mock(return_value=result)
        r=inspect(IMAGE,runner=runner)
        self.assertEqual(r["status"],"LOCAL_IMAGE_IDENTIFIED")
        argv=runner.call_args.args[0]
        self.assertEqual(argv, ["docker","image","inspect",IMAGE,"--format",TEMPLATE])
        self.assertFalse(runner.call_args.kwargs["shell"])

    def test_failure_does_not_echo_secrets(self):
        runner=Mock(return_value=Mock(returncode=1,stdout="",stderr="password=SECRET"))
        r=inspect(IMAGE,runner=runner)
        self.assertEqual(r["status"],"BLOCKED")
        self.assertNotIn("SECRET",str(r))

if __name__=="__main__":
    unittest.main()
