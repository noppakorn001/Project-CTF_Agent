import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOLVER = ROOT / "ctf_challenges/cryptohack_archive/solvers/2023_twist_and_shout_solve.py"
VERIFY = ROOT / "ctf_challenges/cryptohack_archive/solvers/2023_twist_and_shout_verify.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TwistAndShoutTests(unittest.TestCase):
    def test_extension_lift_and_component_order(self):
        solver = load(SOLVER, "twist_solver")
        point = solver.lift_x(1)
        self.assertIsNotNone(point)
        self.assertIsNone(solver.pmul(point, solver.ORDER))
        for factor in solver.ORDER_FACTORS:
            self.assertIsNotNone(solver.pmul(point, solver.ORDER // factor))

    def test_independent_verifier_replays_fixture(self):
        solver = load(SOLVER, "twist_solver_fixture")
        verifier = load(VERIFY, "twist_verifier")
        inner = b"7w1st_&&_sh0ut!"
        scalar = int.from_bytes(inner, "big")
        xz = solver.pmul(solver.lift_x(1), scalar)
        assert xz is not None
        response = xz[0][0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps({
                "host": "archive.cryptohack.org",
                "port": 11718,
                "input_x": 1,
                "response_x": response,
                "twist_order": solver.ORDER,
                "scalar": scalar,
                "inner_hex": inner.hex(),
                "flag": "ECSC{" + inner.decode() + "}",
            }))
            self.assertEqual(verifier.verify(path), "ECSC{7w1st_&&_sh0ut!}")


if __name__ == "__main__":
    unittest.main()
