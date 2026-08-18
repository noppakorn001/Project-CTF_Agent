import unittest

from ctf_agent.web_solvers import solve_web_sources


class WebSolverTests(unittest.TestCase):
    def test_extracts_routes_parameters_security_signals_and_flag(self) -> None:
        result = solve_web_sources(
            [
                {
                    "name": "capture.html",
                    "text": "HTTP/1.1 200 OK\nSet-Cookie: sid=abc\n\n"
                    "<a href='/profile?id=7'>profile</a>"
                    "<form action='/login' method='POST'>"
                    "<input name='user_id'><input name='password'>"
                    "</form>"
                    "<!-- CTF{web_local_flag} -->"
                    "<script>location.href='/admin?role=user'</script>",
                    "sha256": "fixture-sha",
                }
            ],
            flag_format="CTF{...}",
        )

        paths = {route["path"] for route in result["routes"]}
        self.assertIn("/profile", paths)
        self.assertIn("/login", paths)
        self.assertIn("/admin", paths)
        self.assertNotIn("/html", paths)
        self.assertNotIn("/form", paths)
        self.assertIn("id", result["parameters"])
        self.assertIn("user_id", result["parameters"])
        signal_kinds = {signal["kind"] for signal in result["signals"]}
        self.assertIn("cookie_missing_httponly", signal_kinds)
        self.assertIn("cookie_missing_secure", signal_kinds)
        self.assertIn("authorization_surface", signal_kinds)
        self.assertIn("html_comments", signal_kinds)
        self.assertIn("client_script", signal_kinds)
        self.assertEqual([item["value"] for item in result["candidates"]], ["CTF{web_local_flag}"])
        self.assertTrue(result["candidates"][0]["evidence_id"])

    def test_is_bounded_and_handles_malformed_markup(self) -> None:
        result = solve_web_sources(
            [{"name": "broken.html", "text": "<form><input name='x'" + "A" * 100_000}],
            flag_format="CTF{...}",
        )
        self.assertEqual(result["source_count"], 1)
        self.assertLessEqual(len(result["routes"]), 96)
        self.assertLessEqual(len(result["parameters"]), 128)


if __name__ == "__main__":
    unittest.main()
