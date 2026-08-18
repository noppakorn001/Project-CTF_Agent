# Bandit level-to-technique map

This is a generalized map derived from the official [Bandit landing page](https://overthewire.org/wargames/bandit/)
and its linked level-goal pages. It intentionally omits passwords, flags,
writeups, and exact instance transcripts. Level 34 is not present on the
official site at the time of review.

| Levels | Skill signal | Deterministic route |
| --- | --- | --- |
| 0 | SSH on a non-standard port | Confirm host/port scope; use key/value only in the temporary session. |
| 1 | Read a normal file | Enumerate the home directory; inspect with `ls`, `file`, `cat`. |
| 2 | Filename begins with `-` | Use `--` or an explicit `./` path; never pass the filename as an option. |
| 3 | Spaces in a filename | Quote the complete path or use shell escaping. |
| 4 | Hidden file | Include dotfiles (`ls -la`, bounded `find`). |
| 5 | Find the human-readable entry | Check `file`/`strings` across the small directory. |
| 6 | File predicates | Combine bounded `find` predicates for size, type, readability, and executable mode. |
| 7 | Ownership and size | Use `find` with user/group/size, then verify `stat`. |
| 8 | Marker in a large text file | Use `grep -n` with the literal marker and preserve the line. |
| 9 | Unique line | Use `sort | uniq -c` and inspect the count-one candidate. |
| 10 | Human-readable string in binary | Use bounded `strings` and filter the documented marker. |
| 11 | Base64 | Strict-decode one layer and verify the decoded bytes. |
| 12 | ROT13 | Apply the involutive 13-letter rotation with `tr` or a local helper. |
| 13 | Repeated compression/hexdump | Work in `mktemp -d`; reverse hex and identify/decompress one layer per iteration. |
| 14 | SSH private key handoff | Copy only to a temporary path, set restrictive mode, and use `ssh -i`. |
| 15 | Local plaintext TCP | Send exactly one line to the stated localhost port with a timeout. |
| 16 | Local TLS service | Use `openssl s_client` and parse the bounded response; distinguish TLS from plaintext. |
| 17 | Bounded local port discovery | Probe only the stated localhost range, then test the listening candidates for TLS. |
| 18 | Diff two files | Use `diff` and inspect the one changed line; do not copy secrets into the repo. |
| 19 | SSH command/shell behavior | Read the login error and use a safe command/session form in the authorized VM. |
| 20 | Setuid helper | Inspect usage and effective identity; run only the documented challenge-local action. |
| 21 | Setuid plus local callback | Start a disposable listener on the exact local port, send the expected prior credential, and capture one response. |
| 22 | Cron configuration | Read the relevant `/etc/cron.d` entry and trace the invoked program/data flow. |
| 23 | Cron shell script | Review the script, ownership, working directory, and cleanup behavior before a bounded test. |
| 24 | Cron-owned script drop | Create a minimal temporary script with restrictive permissions; retain a copy because the job removes it. |
| 25 | Four-digit PIN protocol | Reuse one authorized connection and enumerate exactly 0000–9999 with a strict response parser. |
| 26 | Restricted login shell | Identify shell/editor behavior, then use a documented disposable-session escape. |
| 27 | Post-escape shell | Inspect the resulting home directory and read only the intended challenge file. |
| 28 | Git repository | Clone only the explicitly provided repo locally; inspect tracked files and metadata. |
| 29 | Git history | Compare commits, branches, and tags; check removed/changed content locally. |
| 30 | Git refs/hidden metadata | Inspect refs and object history; avoid external search or solution repositories. |
| 31 | Git tag/object details | Enumerate local tags/objects and verify the relevant object content. |
| 32 | Repository-controlled submission | Follow the stated file/branch contract; keep credentials and output local. |
| 33 | Uppercase/restricted shell | Determine the actual shell grammar and use a minimal safe escape to inspect state. |
| 34 | No level | Do not invent a route or claim completion; the official page says it does not exist. |

## Generalization checklist

For any new Unix CTF challenge, record: user and group IDs, current directory,
shell, file metadata, exact scope, input/output relation, command cap, and a
replay check. Avoid broad filesystem scans and do not treat a successful
privilege boundary in a training VM as authorization to test a real host.
