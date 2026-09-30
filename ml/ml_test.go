// SPDX-License-Identifier: AGPL-3.0-only

package ml_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/ml"
	"github.com/lazaretemail/lazaret/mql"
)

// A text capability must be sent text, not bytes.
//
// This is the test that was missing. The client decided what to send by asking the
// argument whether it could be bytes — and mql.Value.AsBytes succeeds on a string,
// returning its bytes. So every message body was sent in the image field with the
// text field empty, the service reported intents, topics and tags unavailable
// because it had been handed nothing to classify, and all 358 corpus rules that read
// .intents were silently indeterminate on a deployment where the model was loaded
// and answering correctly.
//
// Nothing caught it: the service's own tests call it directly, and the client's tests
// did not exist. It took ingesting a message through the whole stack and noticing
// that a capability reported as loaded was reported as missing.
func TestTextCapabilitiesAreSentText(t *testing.T) {
	var got struct {
		Text    string            `json:"text"`
		Image   []byte            `json:"image"`
		Options map[string]string `json:"options"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"intents":[{"name":"cred_theft","confidence":"high"}]}`))
	}))
	defer srv.Close()

	c := ml.New(&ml.Options{Address: srv.URL})
	body := "Your password expires today, verify your account."

	for _, cap := range []enrich.Capability{
		enrich.CapMLNLUClassifier,
		enrich.CapBetaMLTopic,
		enrich.CapMLMacroClassifier,
		enrich.CapBetaTranslate,
	} {
		got.Text, got.Image = "", nil
		if _, err := c.Enrich(context.Background(), cap, []mql.Value{mql.StringValue(body)}, nil); err != nil {
			t.Fatalf("%s: %v", cap, err)
		}
		if got.Text != body {
			t.Errorf("%s was sent text %q, want the body", cap, got.Text)
		}
		if len(got.Image) != 0 {
			t.Errorf("%s was sent %d bytes as an image; a string is not a picture", cap, len(got.Image))
		}
	}
}

// Brand detection is the one that does take an image, and it must still get one.
func TestLogoDetectIsSentTheImage(t *testing.T) {
	var got struct {
		Text  string `json:"text"`
		Image []byte `json:"image"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"brands":[]}`))
	}))
	defer srv.Close()

	png := []byte("\x89PNG\r\n\x1a\n" + "not really a png, but bytes")
	c := ml.New(&ml.Options{Address: srv.URL})
	if _, err := c.Enrich(context.Background(), enrich.CapMLLogoDetect,
		[]mql.Value{mql.BytesValue(png)}, nil); err != nil {
		t.Fatal(err)
	}
	if string(got.Image) != string(png) {
		t.Errorf("logo detection was sent %d image bytes, want %d", len(got.Image), len(png))
	}
}

// A capability that answers part of itself must not be reported as wholly missing,
// and the field names must reach the evaluator qualified.
func TestPartialAnswerNamesTheAccessor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"entities":[{"name":"urgency"}],"language":"english","unavailable":["intents","topics"]}`))
	}))
	defer srv.Close()

	c := ml.New(&ml.Options{Address: srv.URL})
	v, err := c.Enrich(context.Background(), enrich.CapMLNLUClassifier,
		[]mql.Value{mql.StringValue("some text")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Reading an answered field works.
	if v.Field("language").IsNull() {
		t.Error("language was answered and should not be null")
	}
	// Reading an unanswered one is null, and knows which capability owes it.
	got := v.Field("intents")
	if !got.IsNull() {
		t.Error("intents was not answered and should be null")
	}
	if got.Unavailable() != "ml.nlu_classifier.intents" {
		t.Errorf("unavailable = %q, want ml.nlu_classifier.intents", got.Unavailable())
	}
}
