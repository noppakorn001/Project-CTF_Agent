# MT19937 offset prediction from two chosen outputs

Some challenge services reveal two selected `random.getrandbits(32)` values
from a fixed prefix, then ask for a later value.  For CPython MT19937, choose
outputs whose state positions align with one twist recurrence.  In TETCTF's
2020 service, outputs 1396 and 1792 expose state words 148 and 544, while the
requested output 2019 is word 147 after the following twist.

Untemper the two observations.  The twist relation uses all bits of word 544,
the low 31 bits of word 148, and only the unknown high bit of word 147.  Thus
there are exactly two predictions; retry a fresh instance after a wrong guess.

Always validate the inverse tempering against a local `random.Random` fixture,
keep retries bounded, and record the observed words and both candidates for an
independent verifier.  Do not treat a public writeup's flag as proof: verify the
candidate against a live authorized service and preserve the transcript.
