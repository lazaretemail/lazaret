// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math/bits"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// campaignMessage builds the parts of a model the fingerprint looks at.
func campaignMessage(subject, display, senderDomain, linkDomain string) *mdm.MessageDataModel {
	m := &mdm.MessageDataModel{
		Subject: &mdm.Subject{Subject: mdm.Ptr(subject)},
		Sender: &mdm.SenderMailbox{
			DisplayName: mdm.Ptr(display),
			Email: &mdm.EmailAddress{
				Email:  mdm.Ptr("noreply@" + senderDomain),
				Domain: &mdm.Domain{Domain: senderDomain, RootDomain: mdm.Ptr(senderDomain)},
			},
		},
	}
	if linkDomain != "" {
		m.Body = &mdm.Body{Links: []*mdm.Link{{
			HrefURL: &mdm.URL{
				Domain: &mdm.Domain{Domain: linkDomain, RootDomain: mdm.Ptr(linkDomain)},
			},
		}}}
	}
	return m
}

func distance(a, b uint64) int { return bits.OnesCount64(a ^ b) }

// The same attack with the details rotated stays one campaign.
//
// This is what the feature is for. A campaign personalises the invoice number and sends
// from a different throwaway mailbox each time; nothing structural changes. If those two
// fingerprints are far apart, the grouping is worthless.
func TestRotatedDetailsKeepOneFingerprint(t *testing.T) {
	a := Fingerprint(campaignMessage(
		"Invoice 40118 is overdue", "Accounts Payable", "billing-notice.test", "pay-now.test"))
	b := Fingerprint(campaignMessage(
		"Invoice 99274 is overdue", "Accounts Payable", "billing-notice.test", "pay-now.test"))

	if d := distance(a, b); d > maxCampaignDistance {
		t.Errorf("the same campaign with a different invoice number is %d bits apart, "+
			"over the %d-bit threshold", d, maxCampaignDistance)
	}
}

// Unrelated mail does not get merged.
//
// The failure that matters. A campaign group is something an analyst may action
// wholesale, so pulling a legitimate message into one is far worse than leaving a
// campaign split — which is only the status quo.
func TestUnrelatedMailIsNotOneCampaign(t *testing.T) {
	phish := Fingerprint(campaignMessage(
		"Invoice 40118 is overdue", "Accounts Payable", "billing-notice.test", "pay-now.test"))
	real := Fingerprint(campaignMessage(
		"Lunch on Thursday?", "Dana Whitfield", "example.test", ""))

	if d := distance(phish, real); d <= maxCampaignDistance {
		t.Errorf("a lunch invitation and an invoice lure are %d bits apart, inside the "+
			"%d-bit threshold", d, maxCampaignDistance)
	}
}

// A message with nothing distinctive gets no fingerprint at all.
//
// Zero is reserved for that, and the store leaves such messages out of clustering. If
// they shared a fingerprint instead, every featureless message in the corpus would form
// one enormous campaign — which is both useless and the most dangerous group to offer
// somebody a bulk action on.
func TestFeaturelessMessagesAreNotACampaign(t *testing.T) {
	if fp := Fingerprint(&mdm.MessageDataModel{}); fp != 0 {
		t.Errorf("a message with no subject, sender, links or attachments got fingerprint %x", fp)
	}
}

// Clustering groups the campaign and leaves the rest alone.
func TestClusterGroupsOnlyWhatBelongsTogether(t *testing.T) {
	now := time.Now().UTC()
	var rows []store.CampaignMember
	for i := 0; i < 9; i++ {
		msg := campaignMessage(
			fmt.Sprintf("Invoice %d0118 is overdue", i+1),
			"Accounts Payable", "billing-notice.test", "pay-now.test")
		rows = append(rows, store.CampaignMember{
			MessageID:   fmt.Sprintf("phish-%d", i),
			ReceivedAt:  now.Add(time.Duration(i) * time.Minute),
			Subject:     *msg.Subject.Subject,
			SenderEmail: fmt.Sprintf("a%d@billing-notice.test", i),
			Verdict:     "malicious",
			Fingerprint: Fingerprint(msg),
		})
	}
	// Ordinary mail, each different from the others.
	for i, subject := range []string{"Lunch on Thursday?", "Q3 board pack attached", "Re: parking permits"} {
		msg := campaignMessage(subject, "Dana Whitfield", "example.test", "")
		rows = append(rows, store.CampaignMember{
			MessageID:   fmt.Sprintf("real-%d", i),
			ReceivedAt:  now,
			Subject:     subject,
			Fingerprint: Fingerprint(msg),
		})
	}

	got := Cluster(rows)
	if len(got) != 1 {
		t.Fatalf("expected one campaign, got %d: %+v", len(got), got)
	}
	if got[0].Size != 9 {
		t.Errorf("campaign has %d messages, want the 9 that were sent", got[0].Size)
	}
	if len(got[0].Senders) != 9 {
		t.Errorf("campaign lists %d senders; the rotating pool is what makes it one campaign", len(got[0].Senders))
	}
	for _, m := range got[0].Messages {
		if m.MessageID[:5] != "phish" {
			t.Errorf("legitimate message %s was pulled into the campaign", m.MessageID)
		}
	}
}

// Two lookalike messages are a coincidence; a group has to be worth calling a campaign.
func TestAPairIsNotACampaign(t *testing.T) {
	msg := campaignMessage("Invoice 40118 is overdue", "Accounts Payable",
		"billing-notice.test", "pay-now.test")
	fp := Fingerprint(msg)
	rows := []store.CampaignMember{
		{MessageID: "a", Fingerprint: fp, ReceivedAt: time.Now()},
		{MessageID: "b", Fingerprint: fp, ReceivedAt: time.Now()},
	}
	if got := Cluster(rows); len(got) != 0 {
		t.Errorf("two similar messages were reported as a campaign: %+v", got)
	}
}

// A campaign that was judged inconsistently says so.
//
// The reason to group at all: twenty-nine judged malicious and one not is a miss with
// its own evidence attached, and it is invisible message by message.
func TestACampaignReportsASplitVerdict(t *testing.T) {
	now := time.Now().UTC()
	fp := Fingerprint(campaignMessage("Invoice 40118 is overdue", "Accounts Payable",
		"billing-notice.test", "pay-now.test"))

	rows := []store.CampaignMember{}
	for i := 0; i < 5; i++ {
		v := "malicious"
		if i == 4 {
			v = "none"
		}
		rows = append(rows, store.CampaignMember{
			MessageID:   fmt.Sprintf("m-%d", i),
			ReceivedAt:  now.Add(time.Duration(i) * time.Minute),
			Verdict:     v,
			Fingerprint: fp,
		})
	}

	got := Cluster(rows)
	if len(got) != 1 {
		t.Fatalf("expected one campaign, got %d", len(got))
	}
	if got[0].Verdicts["malicious"] != 4 || got[0].Verdicts["none"] != 1 {
		t.Errorf("verdict split reported as %v, want 4 malicious and 1 none", got[0].Verdicts)
	}
}

// A campaign that rotates its sending domain stays one campaign.
//
// This is the case that failed against the live deployment, and it is the one that
// matters most: rotating the sending domain is the cheapest thing a campaign does.
// The first version weighted the sender's root domain, which put four otherwise
// identical messages into four groups — a feature an attacker changes for free was
// able to split the group.
func TestRotatingTheSendingDomainDoesNotSplitACampaign(t *testing.T) {
	fps := make([]uint64, 4)
	for i := range fps {
		fps[i] = Fingerprint(campaignMessage(
			fmt.Sprintf("Invoice %d0118 is overdue", i+1),
			"Accounts Payable",
			fmt.Sprintf("billing-notice-%d.test", i+1), // a new domain every send
			"pay-now-portal.test"))
	}
	for i := 1; i < len(fps); i++ {
		if d := distance(fps[0], fps[i]); d > maxCampaignDistance {
			t.Errorf("send %d is %d bits from send 1; rotating the sending domain "+
				"split the campaign", i+1, d)
		}
	}
}
