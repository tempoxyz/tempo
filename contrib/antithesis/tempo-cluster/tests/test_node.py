"""Check validator/follower launch arguments without building node images."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "node.sh"


class NodeLauncher(unittest.TestCase):
    def test_roles_keep_signing_keys_on_validators_and_follower_identity_on_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            genesis = root / "genesis"
            data = root / "data"
            keys = genesis / "10.21.0.11:8000"
            keys.mkdir(parents=True)
            (keys / "enode.identity").write_text("fixture-peer")
            script = root / "node.sh"
            script.write_text(SOURCE.read_text().replace("/opt/tempo-cluster/genesis", str(genesis)).replace("/data", str(data)))
            tempo = root / "tempo"
            tempo.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
            tempo.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
            for role in ("validator", "follower"):
                with self.subTest(role=role):
                    result = subprocess.run(["bash", str(script), "10.21.0.11", role], env=env,
                                            capture_output=True, text=True, timeout=5, check=True)
                    args = json.loads(result.stdout)
                    self.assertEqual("--consensus.signing-key" in args, role == "validator")
                    self.assertEqual("--consensus.signing-share" in args, role == "validator")
                    self.assertNotIn("--follow.nocertify", args)
                    self.assertEqual(args[args.index("--ws.api") + 1], "all")
                    if role == "follower":
                        self.assertEqual(args[args.index("--follow") + 1], "ws://validator-0:8546")
                        identity = data / "follower-enode.key"
                        self.assertEqual(identity.read_text(), f"{5:064x}")
                        identity.write_text(f"{6:064x}")
                        subprocess.run(["bash", str(script), "10.21.0.15", role], env=env,
                                       capture_output=True, timeout=5, check=True)
                        self.assertEqual(identity.read_text(), f"{6:064x}")
