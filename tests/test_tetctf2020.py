import importlib.util
import json
import random
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOLVER = ROOT / "ctf_challenges/cryptohack_archive/solvers/2020_tetctf2020_solve.py"
VERIFY = ROOT / "ctf_challenges/cryptohack_archive/solvers/2020_tetctf2020_verify.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Tetctf2020Tests(unittest.TestCase):
    def test_untemper_is_inverse_and_two_predictions_include_next_output(self):
        solver = load(SOLVER, "tet_solver")
        rng = random.Random(0x2020)
        values = [rng.getrandbits(32) for _ in range(2020)]
        for value in values[:64]:
            self.assertEqual(solver.untemper(solver.temper(value)), value)
        self.assertIn(values[2019], solver.candidate_predictions(values[1396], values[1792]))

    def test_independent_verifier_accepts_record_and_rejects_tamper(self):
        solver = load(SOLVER, "tet_solver_record")
        verifier = load(VERIFY, "tet_verifier")
        rng = random.Random(7)
        values = [rng.getrandbits(32) for _ in range(2020)]
        candidates = solver.candidate_predictions(values[1396], values[1792])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps({
                "success": {
                    "indices": [1396, 1792],
                    "revealed": [values[1396], values[1792]],
                    "candidates": list(candidates),
                    "guess": values[2019],
                    "flag": "TetCTF{local_fixture}",
                }
            }))
            self.assertEqual(verifier.verify(path), "TetCTF{local_fixture}")
            data = json.loads(path.read_text())
            data["success"]["guess"] ^= 1
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                verifier.verify(path)


if __name__ == "__main__":
    unittest.main()
