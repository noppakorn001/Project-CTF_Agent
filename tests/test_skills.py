from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = REPO_ROOT / ".agents" / "skills"
FRONTMATTER_RE = re.compile(r"\A---\n(?P<meta>.*?)\n---\n", re.DOTALL)
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class SkillStructureTests(unittest.TestCase):
    def test_core_skills_exist(self) -> None:
        expected = {
            "ctf-router",
            "ctf-web",
            "ctf-pwn",
            "ctf-reverse",
            "ctf-crypto",
            "ctf-forensics",
            "ctf-writeup",
        }
        actual = {path.parent.name for path in SKILLS_ROOT.glob("*/SKILL.md")}
        self.assertTrue(expected <= actual, expected - actual)

    def test_skill_frontmatter_links_and_size(self) -> None:
        skill_files = sorted(SKILLS_ROOT.glob("*/SKILL.md"))
        self.assertGreater(len(skill_files), 0)

        for skill_file in skill_files:
            with self.subTest(skill=skill_file.parent.name):
                source = skill_file.read_text(encoding="utf-8")
                self.assertLessEqual(
                    len(source.splitlines()),
                    500,
                    "SKILL.md should use progressive disclosure",
                )
                self.assertNotIn("TODO", source)

                match = FRONTMATTER_RE.match(source)
                self.assertIsNotNone(match, "missing YAML frontmatter")
                metadata: dict[str, str] = {}
                assert match is not None
                for line in match.group("meta").splitlines():
                    key, separator, value = line.partition(":")
                    self.assertEqual(separator, ":", f"invalid metadata line: {line}")
                    metadata[key.strip()] = value.strip()

                self.assertEqual(set(metadata), {"name", "description"})
                self.assertEqual(metadata["name"], skill_file.parent.name)
                self.assertTrue(metadata["description"])

                for target in LINK_RE.findall(source):
                    if target.startswith(("http://", "https://", "#")):
                        continue
                    relative_target = target.split("#", 1)[0]
                    self.assertTrue(
                        (skill_file.parent / relative_target).is_file(),
                        f"missing linked resource: {target}",
                    )

    def test_reference_files_have_no_placeholders(self) -> None:
        for reference in sorted(SKILLS_ROOT.glob("*/references/*.md")):
            with self.subTest(reference=reference.relative_to(REPO_ROOT)):
                source = reference.read_text(encoding="utf-8")
                self.assertNotIn("TODO", source)
                self.assertNotIn("<insert", source.lower())


if __name__ == "__main__":
    unittest.main()
