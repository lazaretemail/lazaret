// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"hash/fnv"
	"math/bits"
	"sort"
	"strings"
	"unicode"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Campaigns: one attack, arriving thirty times.
//
// A phishing campaign is not thirty unrelated messages. It is one message with the
// recipient's name swapped, sent from a rotating pool of addresses, carrying links on
// three hosts that all reach the same place. Triaged one at a time, an analyst looks at
// the same attack thirty times and makes the same decision thirty times, and the
// twenty-ninth is no faster than the first. Grouped, it is one decision.
//
// # Why this is a hash and not a model
//
// The obvious build is sentence embeddings: encode every message, index the vectors,
// cluster by cosine distance. It is also the one that does not survive contact with a
// deployment. It needs a model loaded in the inference service, a vector index beside
// the corpus, a similarity threshold nobody can justify, and a GPU for it to be quick —
// and it answers a question about wording, when what actually identifies a campaign is
// mostly structure: the same link host, the same attachment, the same display name, the
// same shape of subject with one word different.
//
// So: SimHash over structural features. Sixty-four bits per message, computed in
// microseconds with no network and no model, stored beside the message, and compared by
// counting differing bits. It is deterministic, it needs nothing running, and it groups
// the case that matters — the same attack with the details rotated — which is exactly
// what near-duplicate detection was invented for.
//
// What it does not do is find two campaigns that say the same thing in different words.
// A model would. That is a real limit, it is stated here rather than hidden, and it is
// the right trade for a system whose value is that it works on a laptop with no GPU.

// Fingerprint is a message's 64-bit SimHash.
//
// Zero means "no fingerprint": a message with nothing distinctive in it — no subject,
// no links, no attachments, no sender — should not be clustered with every other such
// message, and a shared zero would put all of them in one enormous campaign.
func Fingerprint(msg *mdm.MessageDataModel) uint64 {
	feats := features(msg)
	if len(feats) == 0 {
		return 0
	}

	// SimHash: each feature votes on each bit, weighted, and the sign of the total
	// decides. Similar feature sets differ in few bits; one changed feature moves at
	// most a few of them, which is the property the whole thing rests on.
	var vote [64]int
	for _, f := range feats {
		h := fnv64(f.text)
		for b := 0; b < 64; b++ {
			if h&(1<<uint(b)) != 0 {
				vote[b] += f.weight
			} else {
				vote[b] -= f.weight
			}
		}
	}
	var out uint64
	for b := 0; b < 64; b++ {
		if vote[b] > 0 {
			out |= 1 << uint(b)
		}
	}
	if out == 0 {
		// A message whose votes cancelled exactly. Vanishingly unlikely, but zero is
		// reserved for "no fingerprint", so nudge it rather than let it join the
		// unfingerprinted.
		out = 1
	}
	return out
}

// feature is one thing about a message and how much it should count.
type feature struct {
	text   string
	weight int
}

// features is what a campaign is recognised by.
//
// The weights say what an attacker can cheaply rotate and what they cannot. The
// impersonated identity and the infrastructure the links reach are the campaign; the
// recipient is not part of it at all — it is the thing being varied.
//
// # Who sent it is deliberately not in here
//
// The first version weighted the sender's root domain, on the reasoning that forty
// throwaway mailboxes on one domain are one campaign. Run against four messages that
// were identical but for the sending domain, it put them in four groups: the sender
// feature was heavy enough to flip bits that the three shared features did not pin,
// and rotating the sending domain is the single most common thing a campaign does.
// A feature an attacker changes for free must not be able to split the group.
//
// The senders are not lost — they are counted on the group, where "nine messages, four
// senders, one link host" is the sentence that makes it reviewable.
func features(msg *mdm.MessageDataModel) []feature {
	var out []feature
	add := func(w int, parts ...string) {
		for _, p := range parts {
			if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
				out = append(out, feature{text: p, weight: w})
			}
		}
	}

	if s := msg.Subject; s != nil && s.Subject != nil {
		// Shingled rather than taken whole, so "Invoice 4471 overdue" and
		// "Invoice 8812 overdue" are near neighbours instead of unrelated. Campaigns
		// vary a number, a name or a company in an otherwise fixed subject, which is
		// the single most common thing they do.
		for _, sh := range shingles(normalise(*s.Subject), 3) {
			add(3, sh)
		}
	}

	// The impersonated identity, which is the point of the campaign and the last
	// thing its author wants to change.
	if s := msg.Sender; s != nil && s.DisplayName != nil {
		add(5, "display:"+normalise(*s.DisplayName))
	}

	// Where the links go. Infrastructure is what a campaign actually shares, and it
	// is what costs the sender money to change.
	//
	// The root domain carries the weight and the host is a lighter echo of it, so a
	// campaign rotating subdomains under one registration stays together while two
	// campaigns on genuinely different infrastructure stay apart.
	roots, hosts := map[string]bool{}, map[string]bool{}
	var links []*mdm.Link
	if msg.Body != nil {
		links = msg.Body.Links
	}
	for _, l := range links {
		if l == nil || l.HrefURL == nil || l.HrefURL.Domain == nil {
			continue
		}
		if root := mdm.Deref(l.HrefURL.Domain.RootDomain); root != "" && !roots[root] {
			roots[root] = true
			add(7, "linkdom:"+root)
		}
		if host := l.HrefURL.Domain.Domain; host != "" && !hosts[host] {
			hosts[host] = true
			add(2, "linkhost:"+host)
		}
	}

	// The attachment itself, by content. Two messages carrying byte-identical files
	// are the same send however the covering note was reworded.
	for _, a := range msg.Attachments {
		if a == nil {
			continue
		}
		if a.MD5 != nil && *a.MD5 != "" {
			add(8, "attach:"+*a.MD5)
			continue
		}
		if a.FileName != nil {
			add(3, "attachname:"+normalise(*a.FileName))
		}
	}
	return out
}

// normalise strips what a campaign varies: digits, punctuation and runs of space.
//
// Digits go entirely. An invoice number, an order reference, a ticket id and a dollar
// amount are the fields a campaign personalises, and keeping them would make every
// message in a campaign a different message — which is precisely the failure this is
// here to avoid.
func normalise(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsDigit(r):
			// Dropped, not replaced: "invoice 4471" and "invoice 88" then agree.
		case unicode.IsLetter(r):
			b.WriteRune(r)
			space = false
		default:
			if !space {
				b.WriteByte(' ')
				space = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// shingles splits text into overlapping word n-grams.
//
// Overlapping so that inserting one word shifts a few shingles rather than all of them.
// Short text yields itself: a two-word subject has no 3-grams, and dropping it would
// leave the message with no subject feature at all.
func shingles(text string, n int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	if len(words) <= n {
		return []string{strings.Join(words, " ")}
	}
	out := make([]string, 0, len(words)-n+1)
	for i := 0; i+n <= len(words); i++ {
		out = append(out, strings.Join(words[i:i+n], " "))
	}
	return out
}

func fnv64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// maxCampaignDistance is how many of the sixty-four bits may differ for two messages to
// be the same campaign.
//
// Three. Chosen the way every other threshold in this project is: by what it costs to be
// wrong in each direction. Too tight and a campaign splits into singletons, which is the
// status quo and costs nothing new. Too loose and unrelated mail is merged, which puts a
// legitimate message inside a group an analyst is about to action wholesale — a far
// worse failure, and the reason this errs tight.
const maxCampaignDistance = 3

// minCampaignSize is the smallest group worth calling a campaign. Two messages that
// happen to look alike are a coincidence; three is a pattern.
const minCampaignSize = 3

// Campaign is a group of messages that arrived as one attack.
type Campaign struct {
	ID      string `json:"id"`
	Size    int    `json:"size"`
	Subject string `json:"subject,omitempty"`

	// Senders and LinkDomains are what the group has in common, which is what makes
	// it reviewable: "nine messages, four senders, all linking to the same host".
	Senders     []string `json:"senders,omitempty"`
	LinkDomains []string `json:"link_domains,omitempty"`

	First string `json:"first_seen"`
	Last  string `json:"last_seen"`

	// Verdicts counts what the deployment concluded about each member.
	//
	// The interesting campaign is the split one. Thirty messages where twenty-nine
	// were judged malicious and one was not is a miss with its own evidence attached,
	// and it is invisible message by message.
	Verdicts map[string]int `json:"verdicts,omitempty"`

	// Triage counts what analysts concluded, for the same reason.
	Triage map[string]int `json:"triage,omitempty"`

	Messages []store.CampaignMember `json:"messages"`
}

// maxCampaignMembers caps what one group carries back. A campaign of nine thousand is
// worth knowing about; nine thousand rows in the response is not.
const maxCampaignMembers = 200

// Cluster groups messages by fingerprint.
//
// Banded rather than pairwise. Comparing every message to every other is quadratic, and
// a month of mail at the rate this is designed for is tens of thousands of messages —
// tens of millions of comparisons per page load. Splitting the 64 bits into four 16-bit
// bands and only comparing messages that agree on a whole band makes it linear in
// practice: two fingerprints within three bits must agree on at least one band, by the
// pigeonhole principle, so nothing is missed.
func Cluster(rows []store.CampaignMember) []Campaign {
	// Union-find over the rows.
	parent := make([]int, len(rows))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	for band := 0; band < 4; band++ {
		shift := uint(band * 16)
		buckets := map[uint16][]int{}
		for i, r := range rows {
			if r.Fingerprint == 0 {
				continue
			}
			key := uint16(r.Fingerprint >> shift)
			buckets[key] = append(buckets[key], i)
		}
		for _, idx := range buckets {
			// A band shared by a very large number of messages is not evidence of a
			// campaign; it is a band with no entropy — every message with no links
			// and a two-word subject, say. Comparing them pairwise would be the
			// quadratic blow-up this scheme exists to avoid, and merging them would
			// be wrong anyway.
			if len(idx) > 500 {
				continue
			}
			for a := 0; a < len(idx); a++ {
				for b := a + 1; b < len(idx); b++ {
					x, y := rows[idx[a]], rows[idx[b]]
					if bits.OnesCount64(x.Fingerprint^y.Fingerprint) <= maxCampaignDistance {
						union(idx[a], idx[b])
					}
				}
			}
		}
	}

	groups := map[int][]store.CampaignMember{}
	for i, r := range rows {
		root := find(i)
		groups[root] = append(groups[root], r)
	}

	var out []Campaign
	for root, members := range groups {
		if len(members) < minCampaignSize {
			continue
		}
		out = append(out, summarise(rows[root].Fingerprint, members))
	}
	// Biggest first, then most recent: the campaign that is still arriving is the one
	// somebody needs to see.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Last > out[j].Last
	})
	return out
}

func summarise(fp uint64, members []store.CampaignMember) Campaign {
	sort.Slice(members, func(i, j int) bool {
		return members[i].ReceivedAt.Before(members[j].ReceivedAt)
	})

	c := Campaign{
		ID:       campaignID(fp),
		Size:     len(members),
		Subject:  members[0].Subject,
		First:    members[0].ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Last:     members[len(members)-1].ReceivedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Verdicts: map[string]int{},
		Triage:   map[string]int{},
	}

	senders := map[string]bool{}
	domains := map[string]bool{}
	for _, m := range members {
		if m.SenderEmail != "" {
			senders[m.SenderEmail] = true
		}
		for _, d := range m.LinkDomains {
			domains[d] = true
		}
		if m.Verdict != "" {
			c.Verdicts[m.Verdict]++
		}
		if m.Triage != "" {
			c.Triage[m.Triage]++
		}
	}
	c.Senders = sortedKeys(senders)
	c.LinkDomains = sortedKeys(domains)

	if len(members) > maxCampaignMembers {
		// Newest kept, because the ones still arriving are the ones an analyst acts
		// on. Size above is the true count either way.
		members = members[len(members)-maxCampaignMembers:]
	}
	c.Messages = members
	return c
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// campaignID is derived from the fingerprint, so the same campaign keeps the same id
// between page loads and an analyst can link to one.
func campaignID(fp uint64) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[15-i] = hex[(fp>>uint(4*i))&0xf]
	}
	return "c_" + string(b)
}
