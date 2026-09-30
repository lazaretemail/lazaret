# What this does to people's mail

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

Read this before turning on removal. Everything here is about the side of the product
that changes a mailbox rather than the side that reads it.

## Quarantine is custody

Quarantine does not move a message to a folder. It deletes the message from the mailbox
and keeps the only remaining copy in the blob store. Releasing it puts it back.

The alternative — a hidden folder, or a flag on the message — leaves it in reach
of the recipient, of a mail client's offline cache, and of anything syncing the mailbox.
Custody means the copy that exists is the one an operator controls, and releasing is an
action somebody has to take.

Three consequences of that, all of which people notice.

**A message whose bytes are not held cannot be quarantined.** The engine returns 409
rather than deleting something nobody could get back. Custody is written at ingest, before
any verdict exists, so this only affects messages ingested before object storage was
configured. There is an explicit force for the case where you have decided the message
should go regardless.

**A released message comes back as new mail.** Neither IMAP nor Graph can put a message
back where it was, in its original position, with its original read state. It reappears at
the top of the inbox, unread, with a new internal date. No API offers anything better. It
is written down here because recipients ask.

**A released message keeps its verdict.** Releasing makes it unread, which makes the
connector analyse it again, which produces the same malicious verdict — so without help
the analyst's decision is undone within seconds, repeatedly. The engine marks the message
`released` and connectors skip it. The verdict itself is left alone: the rules did fire,
and rewriting history would hide a real detection from every report and every
effectiveness number. So a released message shows as malicious forever and sits in the
inbox, which is the honest reading even though it looks odd on the triage page.

## Removal is off by default, on every mailbox

A mailbox added through the dashboard observes and nothing else until someone turns on
"remove flagged mail" for it.

The reason is the obvious first deployment: somebody points this at a production inbox to
see what it finds. That should not start deleting mail because a rule fired. The cost is
that the default configuration detects and does nothing, which surprises people in the
other direction.

## Adding a Microsoft estate, and pausing one

Adding mailboxes one at a time is fine for six and absurd for six hundred. Under
**Settings → Microsoft 365**, once an application registration is saved, **Read the
directory** lists the tenant's accounts and offers them for collection in bulk.

What it offers is narrower than what Microsoft returns, and the difference is stated on
the page: accounts with no mail address have no Exchange mailbox behind them, disabled
accounts are not in use, and a guest's mail lives in their own organisation's tenant
where this registration cannot read it. All three are left out. What it does *not* try to
decide is whether a licensed account really has a mailbox provisioned — Graph will not say
without a call per user, and guessing would mean either hiding real mailboxes or inventing
certainty. One that turns out not to exist reports itself as unreachable on the next
health tick.

Nothing is selected for you. Four hundred mailboxes is a large thing to configure, and it
should take saying so rather than failing to untick. "Start collecting immediately" can be
turned off to add the estate paused, which is a reasonable way to stage a first
deployment.

**This needs a permission mail collection does not.** Collecting needs `Mail.Read`;
listing accounts additionally needs `User.Read.All`, an application permission granted
with admin consent in Entra ID. A tenant with the first and not the second will see the
directory listing refused while collection works perfectly — so that case is detected and
names the permission, rather than surfacing as "403 Forbidden" and sending somebody off to
re-check a client secret they pasted correctly.

Bulk adding never turns on removal. Letting an automated verdict delete mail is a decision
per mailbox and stays on the mailbox form; a tick box on an onboarding screen that granted
it to four hundred at once would be exactly the wrong place for it.

### Pausing rather than removing

Every mailbox can be paused and resumed from the mailbox list, individually or all at
once. A paused mailbox stops being collected from and keeps everything else — the stored
credential, the folder, the message count — so taking a noisy mailbox out of collection for
an afternoon does not mean destroying its configuration and re-entering a password to put
it back.

Removing a mailbox is the other thing, and it does destroy the credential.

### Sovereign clouds

Which Microsoft cloud a tenant lives in is part of the registration: public, GCC High, DoD
or 21Vianet. It used to be a pair of connector flags, which meant a government tenant
configured its cloud by editing a compose file — the one thing the registration form
exists to avoid. The flags still work for a connector running unmanaged; where both are
present, the registration wins.

## Remediation is queued, not pushed

The engine records the decision. The connector collects it on its next pass, which is one
minute by default (`-reconcile-every`).

So a message is marked quarantined the moment an analyst clicks, and is still in the
inbox until a connector picks the job up. If the connector is down, it stays there. The
Mailboxes page shows the outstanding queue for exactly this reason.

A push would be immediate, but it would require the engine to reach the connector, and
most connectors sit behind a firewall. A remediation retries ten times and then gives up
as `failed`.

## Removal targets every mailbox the message reached

A message addressed to two watched mailboxes was delivered to both, and removing it from
one is a half-done quarantine. The work goes to all of them, and a connector that does not
find it reports success rather than an error. Which mailbox a message arrived in is
recorded at ingest, so the common case is aimed rather than fanned out.

## Microsoft 365: permanent delete, and where it does not exist

The connector uses `POST /messages/{id}/permanentDelete`, which is generally available in
Graph v1.0 and needs only `Mail.ReadWrite`, which the connector already holds. It puts the
message in the **Purges** folder in the dumpster. Outlook and Outlook on the web cannot
reach it, and Recover Deleted Items will not return it, while an administrator with
eDiscovery can still produce it and a mailbox on hold keeps it. That is the shape custody
wants.

The sovereign clouds — US Government L4 and L5, and 21Vianet — do not offer the action.
There the connector falls back to `DELETE`, which is a soft delete the recipient can
undo, and logs a warning. If that is not acceptable in your environment, do not enable
removal there.

The fallback decides whether the action is unsupported by comparing the HTTP status code
as an integer. An earlier version matched on the string `"404"` appearing anywhere in the
error text, and the error text contains the endpoint, so a deployment on port 40407 would
have silently downgraded every removal to a recoverable one while logging that the cloud
was at fault. There is a test for the 403 case specifically, because retrying a
permissions failure as a soft delete is the version of that bug that looks healthy.

## Credentials

Mailbox credentials are encrypted at rest with a key that is generated into the `state`
volume on first start, or supplied as `LAZARET_SECRET_KEY`. Changing the key after
mailboxes exist does not re-encrypt anything; the old credentials become unreadable and
every mailbox has to be entered again.

The connector is a separate process and needs the passwords. It reads them from an engine
endpoint restricted to callers holding an **API token**: a signed-in browser session is
refused there whatever its role, so an XSS in the dashboard cannot reach a credential.
Every read goes to the audit log. The same restriction covers
`/v0/mailboxes/{id}/remediations`, whose responses carry whole original messages.

The rejected alternative was giving the connector its own Postgres connection and the
decryption key, which spreads the key to a second process and makes ingest a second writer
against a schema the engine owns.

## Backups

The custody bucket belongs with the database in a backup policy, not with the caches.
Losing it makes every quarantined message unreleasable.

Two buckets, never one. DuckLake owns the corpus prefix and rewrites and expires it during
compaction; custody objects have to survive untouched until a person releases or purges
them. Sharing a prefix would let a compaction delete mail under legal hold.

The `state` volume holds the credential encryption key and the connector's API token. The
database can be rebuilt from mail. The key cannot be rebuilt from anything.

## Retrospective scans do not act

A history scan walks a mailbox back over a window and analyses what it finds. It records
verdicts and it does not remediate, whatever fires. A message delivered two months ago is
not a delivery decision today, and a sweep that quarantined three hundred old messages
because a new rule landed would be a bad afternoon. There is deliberately no branch in
that code path that removes anything.
