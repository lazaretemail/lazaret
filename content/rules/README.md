<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Lazaret detection content

Rules baked into the engine image.

**Most Lazaret rules do not live here — they live in
[`lazaretemail/rules`](https://github.com/lazaretemail/rules)**, which a fresh install
pulls as a feed alongside Sublime's corpus. That is where to send a new detection. Rules
change on a different clock from the engine, and nobody should need a new binary to get
a new rule or a contributor to touch the platform to send one.

What stays here is the handful that has to survive with no network and no feed sync, so
that a deployment which has never reached GitHub still detects something.

Kept apart from fetched content on purpose. Everything under a rule *feed* is cloned
from somebody else's repository into the engine's state volume, is replaced wholesale
on every sync, and carries that project's licence — Sublime's corpus is MIT, and
editing a file there would be overwritten on the next pull anyway. These are ours,
they are AGPL-3.0 like the rest of the source, and they survive a fresh clone.

A rule here may use the `rdap.*` extensions, which MQL does not have. Such a rule
will not run on Sublime's engine, and that is a deliberate trade recorded in the rule
itself rather than a surprise.
