from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sentinel.signatures import SignatureDatabaseError, load_signature_database


ROOT = Path(__file__).resolve().parents[1]


class SignatureDatabaseTests(unittest.TestCase):
    def test_loads_repository_signatures(self) -> None:
        database = load_signature_database(ROOT / "signatures.json")

        self.assertIn(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            database.sha256,
        )
        self.assertGreaterEqual(len(database.patterns), 1)
        self.assertEqual(database.heuristic_threshold, 5)

    def test_rejects_invalid_signature_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps({"hashes": []}), encoding="utf-8")

            with self.assertRaises(SignatureDatabaseError):
                load_signature_database(path)


if __name__ == "__main__":
    unittest.main()
