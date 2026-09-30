# lazaret-ingest (module 6)

Where mail comes from, and what is done about it.

## This is the module that makes a verdict mean something

Module 2 *records* dispositions: quarantine, release, who decided and why. It doesn't
perform them. Until this service exists, "quarantine" is a row in an audit table while the
message sits in the inbox. This is where the two get joined up.

## Sources

Three connectors, at three different points in a mail system. They're placements rather
than alternatives.

| Source | Where it sits | Needs |
|---|---|---|
| `rspamd` | **inline, before delivery** | Rspamd, and the Lua plugin in `lua/` |
| `imap` | after delivery | an account, nothing else |
| `graph` | after delivery, Microsoft 365 | an app registration |

**Rspamd is the strongest placement**, and the only one where a verdict can stop a
message reaching a mailbox at all. Everything else sees mail that has already been
delivered and can at best move it afterwards, during which a recipient can read it.

**IMAP is the most portable.** It needs no cooperation from the provider beyond an
account, which makes it the universal fallback: a self-hosted Dovecot, a hosted
mailbox, a shared `abuse@` inbox people forward suspicious mail to.

**Graph has two mechanisms and a deployment gets whichever works.** See below.

Google Workspace is deliberately absent. It can be added as a fourth `Source`; nothing
in the interface assumes Microsoft.

## Rspamd

```sh
cp lua/lazaret.lua /etc/rspamd/lua/lazaret.lua
echo "dofile('/etc/rspamd/lua/lazaret.lua')" >> /etc/rspamd/rspamd.local.lua
```

```conf
# /etc/rspamd/local.d/lazaret.conf
lazaret {
  url = "http://lazaret-ingest:8730/rspamd/check";
  secret = "...";
  timeout = 20.0;
}
```

The plugin contributes a score and a symbol, and Rspamd folds it in alongside SPF, DKIM,
Bayes and everything else. It's a contribution rather than an override on purpose. An
operator who has tuned Rspamd shouldn't find this silently outranking all of it.

| Symbol | When | Default score |
|---|---|---|
| `LAZARET_MALICIOUS` | rules fired | 15 critical / 10 high / 6 medium / 2 low |
| `LAZARET_INDETERMINATE` | ran, could not decide | 1 |
| `LAZARET_CLEAN` | nothing matched | 0 |
| `LAZARET_FAIL` | Lazaret unreachable | 0 |

Scores are set against Rspamd's stock thresholds (greylist 4, add_header 6, reject 15),
so the defaults do something sensible before anyone tunes them: critical rejects on its
own, high is close, medium adds a header, low is advisory.

### Failure is a decision, not an accident

An inline scanner is in the delivery path, so what it does when it breaks is part of
its design.

**Unreachable means fail open.** The message is delivered and `LAZARET_FAIL` is inserted
with weight zero. Failing closed would mean an engine restart stops all mail, an outage
more disruptive, more visible and far more likely to get the whole system removed than a
window of missed detection. The zero-weight symbol exists so the failure is still *visible*
in the headers and logs, and can be alerted on. An operator who'd rather fail closed
changes one line in the Lua.

**Indeterminate gets its own symbol.** The engine ran and couldn't decide, because a
capability it needed was unavailable. That's a third answer. Treating it as clean converts
an outage into delivered phishing; treating it as malicious converts an outage into a mail
outage. It scores 1 and names what was missing, so "we found nothing" and "we couldn't
look" never read the same in a report.

## Microsoft 365: webhook, falling back to polling

Webhook is preferred and polling is the fallback, because every way the webhook fails is
environmental and invisible from inside the process: no public URL, a firewall, a reverse
proxy that eats the validation handshake, an admin who hasn't granted the permission. None
of those should mean mail stops being scanned.

So the failover is more than "try once at startup":

- The notification listener starts **before** the first subscribe, because Graph
  validates a subscription by calling the endpoint *during* the create request.
  Getting that handshake wrong is the most common reason a subscription cannot be made.
- Two consecutive rounds of subscription failure switch polling on.
- A **watchdog** notices silence. A subscription can be accepted and then quietly stop
  delivering, since Graph drops one whose endpoint errors and a proxy change can break
  delivery without anyone touching this service. From in here that looks exactly like a
  quiet mailbox, so silence past the watchdog window starts polling anyway while
  re-subscription keeps being attempted.
- Both running briefly is fine. The engine deduplicates by message id, and a gap doesn't
  deduplicate.

Notifications are acknowledged **before** the message is analysed, because Graph
expects a response in seconds and a full rule evaluation takes longer than that budget.

### Two guards worth knowing about

**`clientState`** is checked in constant time on every notification. It's the only thing
distinguishing a real notification from anyone on the internet who has found the endpoint.

**Continuation links are host-checked.** `nextLink` and `deltaLink` are absolute URLs
chosen by the server, and every request carries a bearer token, so following one blindly
would send that token wherever the response said to. Against real Graph this never fires.
It exists because "the server told us to" isn't a reason to hand out a credential.

`-graph-base` and `-graph-login-base` exist because the sovereign clouds aren't on the
public endpoints. GCC High and DoD use `graph.microsoft.us`, and 21Vianet uses
`microsoftgraph.chinacloudapi.cn`. Hardcoding one host quietly makes the connector unusable
for a whole class of tenant.

## IMAP

IDLE when the server offers it, so a new message gets noticed in seconds, and polling when
it doesn't. Same failover shape as Graph and for the same reason: prefer the cheap
mechanism, always keep the reliable one underneath.

Quarantine deletes the message, using `UID EXPUNGE` where the server has UIDPLUS, so a
concurrent client that flagged something else doesn't get its message expunged by this call
as well.

Restoring uses `APPEND`, which means the released message arrives as new mail. IMAP has no
way to put a message back where it was, so this is an honest representation of what
happened rather than a limitation being papered over.

`-imap-tls` is `tls`, `starttls` or `none`. Plaintext is spelled out rather than implied,
and logged loudly at startup. Dovecot on localhost is a real deployment and refusing it
outright would be posturing, but nobody should arrive at plaintext by leaving a field
blank.

## Quarantine takes custody; it does not file

This is the part most worth understanding before deploying it.

A flagged message is **removed from the mailbox** and the engine keeps the only copy.
Releasing puts that copy back, and agreeing with the verdict means simply not doing so.

We rejected the obvious alternative of moving it to a Quarantine folder, because a folder
is still the recipient's mailbox. The message is one click away, it's in search results,
and "quarantined" comes to mean "filed somewhere else". Against a credential phishing page
that isn't a meaningful intervention.

Three consequences follow, and they're the reason this is written down:

- **The engine refuses to quarantine a message it can't reproduce.** Custody is written at
  ingest, before any verdict exists. If the bytes aren't held, the action endpoint returns
  409 rather than deleting something nobody can get back.
- **Remediation is queued, not immediate.** An analyst releases a message in the dashboard,
  which talks to the engine, while the mailbox is reachable only from here. The intent gets
  recorded and this service collects it on its next pass, so the action survives a
  connector that's restarting. The Mailboxes page shows anything decided and not yet done.
- **A released message doesn't get re-quarantined.** Putting it back makes it unread, so it
  gets analysed again and the same rules fire again. The engine marks it released and the
  connector leaves it alone. Without that, the analyst's decision is undone within seconds,
  repeatedly, and the only symptom is a message that won't stay released.

Removal is **off by default** on every mailbox. A connector pointed at a production inbox
to see what it finds shouldn't start deleting from it because a rule fired.

### Microsoft: permanentDelete, not DELETE

Graph offers two removals and the difference is the whole of custody there.

`DELETE` is a soft delete. The message lands in Deleted Items and the recipient pulls it
straight back out, which is filing with extra steps.

`POST .../permanentDelete` puts it in the **Purges** folder in the dumpster, where Outlook
and Outlook on the web can't reach it and Recover Deleted Items won't return it, while an
administrator with eDiscovery can still produce it and a mailbox on hold keeps it. Gone
from the mailbox, still accounted for, which is exactly the shape custody wants. It's
generally available in Graph v1.0 and needs only `Mail.ReadWrite`, which this connector
already holds.

The sovereign clouds don't offer it (US Government L4 and L5, and 21Vianet), so those fall
back to `DELETE` with one warning line, because a weaker removal beats a connector that
can't remediate at all. The fallback triggers on **404 and 501 only**, never on 401 or 403.
Retrying a permissions failure as a soft delete would leave a recoverable copy in every
mailbox while the connector looked healthy.

## Managed mailboxes

`-managed` takes the mailbox list from the engine instead of from flags, so an
administrator adds an inbox in the dashboard rather than by redeploying this service.
It needs `-service-token`: mailbox credentials are readable only by an API token, and
a signed-in browser session is refused at that endpoint whatever its role.

```sh
lazaret-ingest -managed -service-token "$TOKEN" -engine http://lazaret-engine:8700
```

The supervisor reconciles on a timer, starting mailboxes that are new, stopping ones that
were removed or disabled, and restarting ones whose configuration changed. A rotated
password counts as changed, because a connector still authenticating with the old one is a
mailbox that has quietly stopped being read.

The flags still work, and they're still the right way to run a single mailbox from a
shell.

## Testing

The IMAP tests run against a real server, because the interesting behaviour is all in how
a real one answers: whether it advertises IDLE, whether `MOVE` exists, what a UID search
returns after a message has been copied away.

```sh
docker run -d --name greenmail -p 3143:3143 -p 3993:3993 -p 3025:3025 \
  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 \
     -Dgreenmail.users=watch:watchpw@lazaret.test' greenmail/standalone:2.1.0

LAZARET_TEST_IMAP=localhost:3993 LAZARET_TEST_SMTP=localhost:3025 go test ./... -v
```

Graph is tested locally for the parts that actually break: the handshake, the
`clientState` check, the token-leak guard, the polling decision. Its *wire format* isn't
fixture-tested, because a fixture written from Microsoft's documentation would only confirm
what the documentation says. That's the trap recorded in `docs/ARCHITECTURE.md`, and it has
caught this project four times already.
