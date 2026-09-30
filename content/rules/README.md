<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Lazaret detection content

Rules baked into the engine image.

**Most Lazaret rules don't live here.** They live in
[`lazaretemail/rules`](https://github.com/lazaretemail/rules), which a fresh install pulls
as a feed alongside Sublime's corpus, and that's where to send a new detection. Rules change
on a different clock from the engine, and nobody should need a new binary to get a new rule,
or have to touch the platform to send one.

What stays here is the handful that has to survive with no network and no feed sync, so a
deployment which has never reached GitHub still detects something.

They're kept apart from fetched content on purpose. Everything under a rule *feed* is cloned
from somebody else's repository into the engine's state volume, is replaced wholesale on
every sync, and carries that project's licence. Sublime's corpus is MIT, and editing a file
there would be overwritten on the next pull anyway. These are ours, they're AGPL-3.0 like
the rest of the source, and they survive a fresh clone.

A rule here may use the `rdap.*` extensions, which MQL doesn't have. Such a rule won't run
on Sublime's engine, and that's a deliberate trade recorded in the rule itself rather than a
surprise.
