// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Translate answers beta.ml_translate.
//
// Translation is the one capability here with no useful open-weights answer that fits
// in this service. A general translation model is a per-language-pair download in the
// hundreds of megabytes, and the rule that uses this feeds the result straight back
// into the NLU classifier — so a bad translation does not degrade gracefully, it
// silently changes what the classifier is shown.
//
// So this delegates, to a self-hosted LibreTranslate (AGPL-3.0, the same licence as
// this project). Nothing is sent anywhere by default: with no backend configured the
// capability reports unavailable.
//
// # One case is answered without a backend
//
// Text already in the target language is returned unchanged, with source_language set.
// That is not a shortcut around the missing model — it is the correct translation, and
// it is the common case in an English-speaking deployment. It also means the rule that
// uses this keeps working for the mail it was mostly written for while a backend is
// still being decided on.
type Translate struct {
	// Endpoint is a LibreTranslate base URL. Empty disables everything but the
	// same-language case.
	Endpoint string

	// APIKey is optional; most self-hosted instances need none.
	APIKey string

	// Target is the language to translate into.
	Target string

	client *http.Client
}

func NewTranslate(endpoint, apiKey, target string) *Translate {
	if target == "" {
		target = "en"
	}
	return &Translate{
		Endpoint: strings.TrimRight(endpoint, "/"),
		APIKey:   apiKey,
		Target:   target,
		client:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (t *Translate) Capability() string { return "beta.ml_translate" }
func (t *Translate) Close() error       { return nil }

type translateResult struct {
	Text           *string `json:"text,omitempty"`
	SourceLanguage *string `json:"source_language,omitempty"`

	Unavailable bool `json:"unavailable,omitempty"`
}

// languageCodes maps the names this service reports back to the ISO codes
// LibreTranslate expects.
//
// The two vocabularies differ because they answer to different callers: `.language` is
// compared against "english" by the rules, and LibreTranslate wants "en". Keeping one
// table rather than changing either is the only option that leaves both correct.
var languageCodes = map[string]string{
	"english": "en", "spanish": "es", "french": "fr", "german": "de", "italian": "it",
	"portuguese": "pt", "dutch": "nl", "polish": "pl", "swedish": "sv", "danish": "da",
	"norwegian": "nb", "finnish": "fi", "turkish": "tr", "romanian": "ro", "czech": "cs",
	"hungarian": "hu", "indonesian": "id", "vietnamese": "vi", "russian": "ru",
	"greek": "el", "arabic": "ar", "hebrew": "he", "thai": "th", "hindi": "hi",
	"japanese": "ja", "korean": "ko", "chinese": "zh",
}

func (t *Translate) Infer(ctx context.Context, req Request) (any, error) {
	text := req.Text
	if strings.TrimSpace(text) == "" {
		empty := ""
		return translateResult{Text: &empty}, nil
	}

	name, conf := detectLanguage(text)
	code := languageCodes[name]

	// Already in the target language: the identity translation is the right answer.
	if code != "" && code == t.Target && conf > 0.1 {
		out := text
		src := name
		return translateResult{Text: &out, SourceLanguage: &src}, nil
	}

	if t.Endpoint == "" {
		return translateResult{Unavailable: true}, nil
	}

	source := code
	if source == "" {
		source = "auto"
	}
	body, _ := json.Marshal(map[string]string{
		"q": text, "source": source, "target": t.Target, "format": "text",
		"api_key": t.APIKey,
	})
	u, err := url.Parse(t.Endpoint + "/translate")
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(r)
	if err != nil {
		// A configured backend that cannot be reached is unavailable, not empty.
		// Returning the untranslated text would be worse than returning nothing: the
		// caller feeds it to a classifier and would get a confident answer about a
		// language the classifier does not read.
		return translateResult{Unavailable: true}, nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return translateResult{Unavailable: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("libretranslate: %s: %s", resp.Status, strings.TrimSpace(string(raw))[:min(200, len(raw))])
	}

	var out struct {
		TranslatedText string `json:"translatedText"`
		Detected       struct {
			Language string `json:"language"`
		} `json:"detectedLanguage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	res := translateResult{Text: &out.TranslatedText}
	src := name
	if src == "" && out.Detected.Language != "" {
		for n, c := range languageCodes {
			if c == out.Detected.Language {
				src = n
				break
			}
		}
	}
	if src != "" {
		res.SourceLanguage = &src
	}
	return res, nil
}
