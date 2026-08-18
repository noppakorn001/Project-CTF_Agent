from __future__ import annotations

import contextlib
import io
import json
import unittest

from ctf_agent.__main__ import main
from ctf_agent.playbooks import (
    PLAYBOOKS,
    get_playbook,
    list_playbooks,
    suggest_playbooks,
    validate_playbooks,
)


class CryptoPlaybookTests(unittest.TestCase):
    def test_registry_is_unique_and_points_to_existing_scripts(self) -> None:
        identifiers = [playbook.id for playbook in PLAYBOOKS]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual(validate_playbooks(), [])
        self.assertGreaterEqual(len(PLAYBOOKS), 18)

    def test_filter_and_suggestion_are_deterministic(self) -> None:
        rsa_routes = list_playbooks(category="RSA")
        self.assertTrue(rsa_routes)
        self.assertTrue(all(route.family == "rsa" for route in rsa_routes))
        self.assertEqual(
            [route.id for route in list_playbooks(search="wiener")],
            ["rsa/wiener-small-d"],
        )
        suggestions = suggest_playbooks("RSA e=3 ciphertext and modulus")
        self.assertEqual(suggestions[0][0].id, "rsa/exact-low-exponent")
        self.assertGreaterEqual(suggestions[0][1], 2)

    def test_route_exposes_evidence_and_safe_command_template(self) -> None:
        route = get_playbook("rsa/exact-low-exponent")
        self.assertIn("exact integer root", route.first_check)
        self.assertIn("python3", route.command())
        self.assertNotIn("nc ", route.command())
        network_route = get_playbook("oracle/compression-length")
        self.assertTrue(network_route.network_required)
        self.assertEqual(network_route.status, "network-gated")

    def test_cli_lists_json_and_validates_without_network(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["playbooks", "--category", "rsa", "--json"]), 0)
        records = json.loads(output.getvalue())
        self.assertTrue(records)
        self.assertTrue(all(record["family"] == "rsa" for record in records))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["playbooks", "--validate"]), 0)
        self.assertIn("validated", output.getvalue())


if __name__ == "__main__":
    unittest.main()
