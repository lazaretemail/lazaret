// SPDX-License-Identifier: AGPL-3.0-only

// Command lazaret-ml serves the model-backed enrichment capabilities.
//
// It replaces Sublime's bora-lite and hydra-cpu containers and answers the capabilities
// that genuinely need a model:
//
//	ml.nlu_classifier    731 corpus calls   intents, topics, entities, language
//	ml.logo_detect       127                brands visible in a rendered message
//	beta.ml_topic         18                topic labels
//	ml.attack_score        7                a single score
//	ml.macro_classifier    4                is this VBA malicious
//	beta.ml_translate      2                translate a body
//	beta.fuzzy_attack_score 2
//
// Everything in the ml.* namespace that does *not* need a model has already been taken
// out of it and implemented elsewhere, which is most of the volume:
// beta.ml_extract_sensitive_information is patterns and checksums (package sensitive),
// beta.ocr, beta.scan_qr and beta.parse_exif are Strelka scanners, and the observational
// three-quarters of ml.link_analysis is a browser (services/render). What is left here
// is the part that is irreducibly a model's opinion.
//
// # No weights ship with this
//
// The service loads models from a directory and reports a capability as unavailable
// until one is present. That is a deliberate choice, for two reasons.
//
// Licensing: model weights carry their own licence, independent of this code, and an
// AGPL project that bundles weights inherits whatever terms they came with. Keeping them
// out means the licence story stays exactly as clean as the rest of the repository.
//
// Honesty: a weak classifier here is worse than none, and this is not a general claim
// but a specific, demonstrated one. The corpus is full of clauses shaped like
//
//	not any(ml.nlu_classifier(body.current_thread.text).topics,
//	        .name in ("Newsletters and Digests") and .confidence == "high")
//
// written to *exclude* benign mail. A classifier that cannot confidently recognise
// benign mail makes that negation true, and the rule fires because the model was weak.
// The same engine already shipped that exact bug once, by folding a null array into an
// empty one, and it produced a false positive on a real corpus rule. An unavailable
// capability yields null, the rule reports indeterminate, and nobody is misled.
package main

import (
	"runtime/debug"

	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/lazaretemail/lazaret/telemetry"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":8720", "listen address")
	modelDir := flag.String("models", "/var/lib/lazaret/models", "directory of ONNX models")
	maxBytes := flag.Int64("max-bytes", 16<<20, "maximum request body")
	translate := flag.String("translate", "", "LibreTranslate base URL for beta.ml_translate; empty disables it")
	translateKey := flag.String("translate-key", "", "LibreTranslate API key, if the instance needs one")
	translateTo := flag.String("translate-to", "en", "language to translate into")

	// The confidence buckets, exposed because `.confidence == "high"` gates 315
	// places in the rule corpus and the defaults are reasoned rather than measured.
	// `lazaret-ml calibrate < labelled.jsonl` fits them to real mail.
	highRatio := flag.Float64("high-ratio", DefaultThresholds().HighRatio,
		"how far ahead of the runner-up an intent must be to be reported high")
	highProb := flag.Float64("high-prob", DefaultThresholds().HighProb,
		"entailment probability above which a topic or tag is reported high")
	accelerator := flag.String("accelerator", "auto",
		"execution provider: auto (try the fastest the runtime accepts, else CPU), cpu, cuda, tensorrt, rocm, coreml, directml")
	trustSuppression := flag.Bool("trust-benign-suppression", false,
		"allow ml.nlu_classifier to report benign with high confidence, which lets rules suppress on it; "+
			"off by default because a wrong benign silently stops a rule firing")
	calibrate := flag.Bool("calibrate", false,
		"read labelled JSON lines on stdin and report what each threshold would do, then exit")
	hashLogos := flag.String("hash-logos", "",
		"hash every image under <dir>/<Brand>/ and write a logo pack to stdout, then exit; "+
			"the pack has hashes and no images, so it can be shared where the logos cannot")
	hashSource := flag.String("hash-logos-source", "",
		"provenance line recorded in the pack written by -hash-logos")

	warmup := flag.Bool("warmup", true,
		"compile every label set before serving; off makes startup instant and the "+
			"first few messages slow and incomplete")
	flag.Parse()

	// Before the registry is built: hashing images needs no model, no port and no
	// GPU, and somebody generating a pack should not wait for an ONNX runtime.
	if *hashLogos != "" {
		n, err := WritePack(*hashLogos, *hashSource, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lazaret-ml: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "lazaret-ml: %d hash(es) from %s\n", n, *hashLogos)
		return
	}

	// A misconfigured collector must not stop mail being processed: observability
	// is not allowed to take down the thing it observes. Say so loudly and carry on
	// with no-op providers.
	otelShutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Service: "lazaret-ml",
		Version: buildVersion(),
	})
	if err != nil {
		log.Printf("telemetry: disabled, %v", err)
		otelShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			log.Printf("telemetry: shutting down: %v", err)
		}
	}()

	reg, err := LoadRegistry(Options{
		Dir:               *modelDir,
		TranslateEndpoint: *translate,
		TranslateAPIKey:   *translateKey,
		TranslateTarget:   *translateTo,
		Accelerator:       *accelerator,
	})
	if err != nil {
		// Not fatal. A deployment with no weights is a valid deployment: the
		// capabilities that need them report unavailable and the rules that wanted
		// one report indeterminate, which is the designed behaviour rather than an
		// outage.
		log.Printf("lazaret-ml: %v", err)
	}
	if nlu, ok := reg.models["ml.nlu_classifier"].(*NLU); ok {
		nlu.T.HighRatio = *highRatio
		nlu.T.HighProb = *highProb
		nlu.T.TrustSuppression = *trustSuppression
	}
	if !*trustSuppression {
		log.Printf("lazaret-ml: benign is capped at medium confidence, so rules cannot suppress on it; " +
			"pass -trust-benign-suppression once you have measured it against your own mail")
	}

	if *calibrate {
		if err := Calibrate(context.Background(), reg, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "lazaret-ml: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if reg.HasZeroShot() {
		log.Printf("lazaret-ml: entailment model loaded; intents, topics and tags are answerable")
	} else {
		log.Printf("lazaret-ml: no entailment model; ml.nlu_classifier answers entities and language only, " +
			"and intents, topics and tags report unavailable")
	}
	log.Printf("lazaret-ml: capabilities: %v", reg.Names())

	mux := http.NewServeMux()

	// One endpoint per capability, named exactly as the MQL function is, so that a
	// deployment's logs and a rule's text use the same words.
	for _, cap := range Capabilities {
		mux.HandleFunc("POST /v1/"+cap, func(w http.ResponseWriter, req *http.Request) {
			var in Request
			if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, *maxBytes)).Decode(&in); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			out, err := reg.Infer(req.Context(), cap, in)
			if err != nil {
				if errors.Is(err, ErrNoModel) {
					// 501, and the client turns it into enrich.ErrUnavailable. Not 200
					// with an empty result: that would read as "the model looked and
					// found nothing", which is a different and much worse claim.
					writeErr(w, http.StatusNotImplemented, err)
					return
				}
				writeErr(w, http.StatusBadGateway, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		})
	}

	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"available":   reg.Names(),
			"unavailable": reg.Missing(),
			"partial":     reg.Partial(),
			"accelerator": reg.Accelerator(),
		})
	})

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           telemetry.Middleware("lazaret-ml", mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
	}
	// Compile before serving, not on the first message. See warmup.go: the label
	// sets compile independently, so a request answered mid-warm-up silently omits
	// whichever had not finished.
	if *warmup {
		log.Printf("lazaret-ml: warming up; a cold graph cache takes minutes, a warm one seconds")
		if d := Warm(context.Background(), reg); d > 0 {
			log.Printf("lazaret-ml: warm in %s", d.Round(time.Millisecond))
		}
	}

	log.Printf("lazaret-ml listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "lazaret-ml: %v\n", err)
		os.Exit(1)
	}
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// buildVersion reports the revision this binary was built from, for service.version.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	return info.Main.Version
}
