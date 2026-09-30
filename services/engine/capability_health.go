// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"go.opentelemetry.io/otel/metric"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rdap"
)

// Does a capability actually work?
//
// "Attached" and "working" are different claims and the engine used to make only the
// first. A provider was listed because a client had been constructed with an address,
// which says nothing about whether that address resolves, whether the service behind
// it is up, or whether it has the model it needs. For a long time this deployment
// reported strelka among its providers while the engine could not resolve the host at
// all, and the only symptom was a large number of rules quietly reporting
// indeterminate on every message.
//
// That is precisely the failure this platform exists to avoid making, so it should not
// be making it about itself. Every capability is probed with a real call and reported
// as what it is.

// CapabilityState is what one capability can do right now.
type CapabilityState struct {
	Capability string `json:"capability"`
	Provider   string `json:"provider,omitempty"`

	// OK means a real call was answered. Anything else means every rule that needs
	// this capability will report indeterminate.
	OK bool `json:"ok"`

	// Detail says why not, in words an operator can act on.
	Detail string `json:"detail,omitempty"`

	// Rules is how many loaded rules depend on this, which is the number that turns
	// "a provider is down" into "and here is what it costs you".
	Rules int `json:"rules"`

	TookMS int64 `json:"took_ms"`
}

// probeArgs is a harmless argument for each capability.
//
// Real calls, because a ping proves the socket and nothing else: the ML service
// answers /v1/health perfectly well with no model loaded, and a rule that needs
// ml.nlu_classifier does not care that the port is open. Each of these is the
// cheapest genuine request the capability accepts.
func probeArgs(cap enrich.Capability) []mql.Value {
	tinyPDF := []byte("%PDF-1.4\n1 0 obj\n<</Type/Catalog>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n")
	file := mql.FromGo(&mdm.File{
		FileName: mdm.Ptr("probe.pdf"),
		Size:     mdm.Ptr(int64(len(tinyPDF))),
		Raw:      tinyPDF,
	})
	text := mql.StringValue("Please confirm your password to avoid suspension.")

	switch cap {
	case enrich.CapFileExplode, enrich.CapFileExpandArchives, enrich.CapFileOletools,
		enrich.CapBetaOCR, enrich.CapBetaScanQR, enrich.CapBetaParseExif:
		return []mql.Value{file}

	case enrich.CapFileHTMLScreenshot:
		return []mql.Value{mql.BytesValue([]byte("<html><body>probe</body></html>"))}
	case enrich.CapFileMessageScreenshot:
		return []mql.Value{mql.FromGo(&mdm.MessageDataModel{
			Body: &mdm.Body{HTML: &mdm.BodyHTML{Raw: mdm.Ptr("<html><body>probe</body></html>")}},
		})}

	case enrich.CapMLNLUClassifier, enrich.CapMLAttackScore, enrich.CapBetaMLTopic,
		enrich.CapBetaFuzzyScore, enrich.CapBetaTranslate:
		return []mql.Value{text}
	case enrich.CapMLMacroClassifier, enrich.CapMLLogoDetect:
		return []mql.Value{file}
	case enrich.CapMLLinkAnalysis:
		return []mql.Value{mql.StringValue("http://example.com/")}

	case enrich.CapNetworkWhois:
		// A name reserved by RFC 2606, which the client answers definitively
		// without asking any registry — so the probe tests the code path rather
		// than someone else's uptime.
		return []mql.Value{mql.StringValue("example.invalid")}
	case rdap.CapIP:
		// TEST-NET-1, reserved by RFC 5737, which the client answers definitively
		// without asking any registry — the same reasoning as the name above.
		//
		// This probe used to make a real lookup, and that made the capability a
		// report on ARIN's uptime rather than on this engine. Worse, failures are
		// cached for fifteen minutes, so one transient timeout pinned rdap.ip to
		// "down" for a quarter of an hour and every probe after it returned the
		// cached failure in zero milliseconds — a timeout that took no time, which
		// is what gave it away.
		return []mql.Value{mql.StringValue("192.0.2.1")}
	case rdap.CapASN:
		// A private-use AS number, RFC 6996: no registry holds one.
		return []mql.Value{mql.IntValue(64512)}

	case enrich.CapProfileBySender, enrich.CapProfileBySenderEmail,
		enrich.CapProfileBySenderDomain, enrich.CapProfileByReplyTo:
		return []mql.Value{mql.FromGo(&mdm.MessageDataModel{
			Sender: &mdm.SenderMailbox{Email: &mdm.EmailAddress{
				Email:  mdm.Ptr("probe@example.invalid"),
				Domain: &mdm.Domain{Domain: "example.invalid"},
			}},
		})}
	}
	return []mql.Value{text}
}

// healthTTL is how long a probe result stands.
//
// Short, because the point of the thing is to notice a service coming back. Not zero,
// because two pages call this and each probe is a real network round trip — an
// operator refreshing the coverage page should not be generating twenty requests a
// time against their own inference service.
const healthTTL = 20 * time.Second

// CheckCapabilities probes everything the loaded rules need.
//
// Probes run concurrently and under their own deadline: an unreachable service is
// exactly the case this has to report, and it must not take a connection timeout per
// capability to do it.
func (p *Pipeline) CheckCapabilities(ctx context.Context, timeout time.Duration) []CapabilityState {
	p.healthMu.Lock()
	if time.Since(p.healthAt) < healthTTL && p.health != nil {
		cached := p.health
		p.healthMu.Unlock()
		return cached
	}
	p.healthMu.Unlock()

	fresh := p.probeAll(ctx, timeout)

	p.healthMu.Lock()
	p.health, p.healthAt = fresh, time.Now()
	p.healthMu.Unlock()
	return fresh
}

func (p *Pipeline) probeAll(ctx context.Context, timeout time.Duration) []CapabilityState {
	wanted := p.rules().Capabilities()
	counts := p.rules().CapabilityCounts()

	out := make([]CapabilityState, len(wanted))
	var wg sync.WaitGroup
	for i, cap := range wanted {
		wg.Add(1)
		go func(i int, cap enrich.Capability) {
			defer wg.Done()
			out[i] = p.probe(ctx, cap, counts[cap], timeout)
		}(i, cap)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		// Broken first, then by how much of the rule set each one costs: an
		// operator wants the expensive problem at the top, not alphabetical order.
		if out[i].OK != out[j].OK {
			return !out[i].OK
		}
		if out[i].Rules != out[j].Rules {
			return out[i].Rules > out[j].Rules
		}
		return out[i].Capability < out[j].Capability
	})
	return out
}

func (p *Pipeline) probe(ctx context.Context, cap enrich.Capability, rules int, timeout time.Duration) CapabilityState {
	st := CapabilityState{Capability: string(cap), Rules: rules}
	if p.enricher == nil {
		st.Detail = "no enrichment is configured at all"
		return st
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	_, err := p.enricher.Enrich(ctx, cap, probeArgs(cap), nil)
	st.TookMS = time.Since(start).Milliseconds()

	switch {
	case err == nil:
		// A null answer is still an answer: the capability ran and had nothing to
		// say about this particular input, which is what a probe expects.
		st.OK = true
	case errors.Is(err, context.DeadlineExceeded):
		st.Detail = "timed out — the service is not answering"
	default:
		var un *enrich.Unavailable
		if errors.As(err, &un) {
			st.Detail = un.Reason
			if st.Detail == "" {
				st.Detail = "unavailable"
			}
			if un.Err != nil {
				st.Detail += ": " + firstLine(un.Err.Error())
			}
			break
		}
		st.Detail = firstLine(err.Error())
	}
	return st
}

// firstLine keeps a gRPC error, which can run to several hundred characters of
// connection detail, down to the part an operator reads.
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			s = s[:i]
			break
		}
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// reportCapabilityHealth says at startup what will and will not work.
//
// The one line an operator needs on a stack they have just brought up, and the thing
// whose absence made an unreachable Strelka look like normal behaviour for weeks: the
// engine said "enrichment: [... strelka ...]" and a fifth of the rule set silently
// stopped answering.
//
// Printed at startup and not only on request, because nobody queries an endpoint to
// find out whether the thing they just started works — they read the log, decide it
// came up clean, and go and use it.
//
// On its own this line lies by omission, which is why watchCapabilityHealth exists.
// The engine does not wait for the renderer or the model service, and it should not:
// mail still has to be judged while they come up. But it means this probe runs while
// they are still starting, reports whatever was not ready yet, and is then never
// corrected — so an operator reads "237 rules cannot run", the stack finishes booting
// thirty seconds later, and the log still says the same thing an hour on.
func reportCapabilityHealth(ctx context.Context, p *Pipeline) {
	health := p.CheckCapabilities(ctx, 10*time.Second)
	if len(health) == 0 {
		return
	}

	var down []CapabilityState
	var lost int
	for _, h := range health {
		if !h.OK {
			down = append(down, h)
			lost += h.Rules
		}
	}

	if len(down) == 0 {
		log.Printf("  capabilities: all %d answered; every loaded rule can run", len(health))
		return
	}

	log.Printf("  capabilities: %d of %d NOT answering — %d rules cannot run and will "+
		"report indeterminate", len(down), len(health), lost)
	for _, h := range down {
		log.Printf("      %-32s %4d rules   %s", h.Capability, h.Rules, h.Detail)
	}
}

// reportInference says at startup what the model service is running on.
//
// Printed because the alternative is finding out by wondering why every message
// takes eight seconds. A zero-shot pass costs the number of candidate labels rather
// than the length of the text, so it is the largest single cost in an analysis, and
// it is the piece that a GPU makes almost free — but a runtime built without a GPU
// provider refuses every one of them and falls back to the CPU without complaint.
// The result is correct and slow, which is the hardest kind of problem to notice.
func reportInference(ctx context.Context, p *Pipeline) {
	if p.ml == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	inf, err := p.ml.Inference(ctx)
	if err != nil || inf == nil {
		return
	}
	switch {
	case inf.OnGPU():
		log.Printf("  inference: %s", inf.Provider)
	case len(inf.Tried) > 0:
		log.Printf("  inference: cpu — %s %s offered and refused by the runtime; "+
			"the classifier is the slowest part of an analysis and a GPU provider "+
			"would change that",
			strings.Join(inf.Tried, ", "),
			map[bool]string{true: "were", false: "was"}[len(inf.Tried) > 1])
	default:
		log.Printf("  inference: cpu")
	}
}

// watchCapabilityHealth keeps the startup picture honest.
//
// Two jobs. The first is the grace period: dependencies are still starting when the
// engine probes them, so for a short while afterwards it looks again and says so
// when the picture improves. The second is the long run — a renderer that dies at
// three in the morning takes 237 rules with it, and the only signal today is that
// results quietly become indeterminate.
//
// Only transitions are logged. A line every minute saying everything is still fine
// is how an operator learns to ignore the log.
func watchCapabilityHealth(ctx context.Context, p *Pipeline) {
	const (
		grace      = 3 * time.Minute
		fastEvery  = 5 * time.Second
		slowEvery  = 60 * time.Second
		probeLimit = 10 * time.Second
	)

	was := map[string]bool{}
	for _, h := range p.CheckCapabilities(ctx, probeLimit) {
		was[h.Capability] = h.OK
		recordCapabilityState(ctx, h)
	}

	started := time.Now()
	for {
		every := slowEvery
		if time.Since(started) < grace {
			every = fastEvery
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}

		now := p.CheckCapabilities(ctx, probeLimit)
		for _, h := range now {
			recordCapabilityState(ctx, h)
		}
		recovered, lost := capabilityTransitions(was, now)
		regained := 0
		for _, h := range recovered {
			regained += h.Rules
		}

		for _, h := range recovered {
			log.Printf("capability recovered: %s — %d rules can run again", h.Capability, h.Rules)
		}
		for _, h := range lost {
			log.Printf("capability lost: %s — %d rules will now report indeterminate: %s",
				h.Capability, h.Rules, h.Detail)
		}
		if len(recovered) > 0 && len(lost) == 0 {
			if down := countDown(was); down == 0 {
				log.Printf("capabilities: all answering again; %d rules recovered — "+
					"the startup report above is out of date", regained)
			}
		}
	}
}

// capabilityTransitions reports what changed since the last probe, and updates was
// in place.
//
// Separated from the loop so the interesting part — only a change is worth saying —
// can be tested without waiting on timers or standing up enrichment services. A
// capability seen for the first time is not a transition: on the first pass every
// capability would otherwise be reported as having just changed.
func capabilityTransitions(was map[string]bool, now []CapabilityState) (recovered, lost []CapabilityState) {
	for _, h := range now {
		name := h.Capability
		prev, seen := was[name]
		was[name] = h.OK
		if !seen || prev == h.OK {
			continue
		}
		if h.OK {
			recovered = append(recovered, h)
		} else {
			lost = append(lost, h)
		}
	}
	return recovered, lost
}

func countDown(state map[string]bool) int {
	n := 0
	for _, ok := range state {
		if !ok {
			n++
		}
	}
	return n
}

// recordCapabilityState publishes availability as a metric, so "which capabilities
// are down right now" is answerable without reading a log or calling an endpoint.
func recordCapabilityState(ctx context.Context, h CapabilityState) {
	var up int64
	if h.OK {
		up = 1
	}
	metricCapabilityUp.Record(ctx, up, metric.WithAttributes(attrCapability.String(h.Capability)))
}
