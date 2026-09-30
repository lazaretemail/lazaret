// SPDX-License-Identifier: AGPL-3.0-only

//go:build onnx

package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"github.com/daulet/tokenizers"
	ort "github.com/yalue/onnxruntime_go"
)

// The entailment runtime.
//
// Zero-shot rather than a trained classifier, because the label vocabulary comes from
// the rule corpus and no labelled email set exists for it. The model is asked, for each
// label, whether the message entails "This text is <description>." — so adding a label
// is writing a sentence, not collecting data.
//
// This costs one forward pass per label. That is the trade: 44 labels at roughly 15ms
// each is most of a second per message, which is why the engine caches enrichment per
// message and why intents, topics and tags are scored in one batch rather than three.

type onnxZeroShot struct {
	tok     *tokenizers.Tokenizer
	session *ort.DynamicAdvancedSession

	cls, sep, pad uint32
	maxLen        int

	// One session, and ONNX Runtime sessions are not safe to call concurrently
	// unless configured for it. Serialised rather than pooled: the engine already
	// caches per message, so the contention is between messages and a queue is the
	// honest way to handle a fixed amount of CPU.
	// On a GPU the serialisation matters less than it looks: the card is the
	// bottleneck, so a second concurrent session would contend for the same silicon
	// and the same memory. Queueing in front of it costs little and avoids running
	// out of VRAM under load.
	mu sync.Mutex

	// accel records what the runtime actually accepted, for the log and the
	// capabilities endpoint.
	accel accelerator
}

var initONNX sync.Once
var initErr error

// openZeroShot loads the entailment model from dir.
//
// Two files, named for what they are rather than for a capability, because one model
// answers intents, topics and tags:
//
//	zeroshot.onnx            the exported graph
//	zeroshot.tokenizer.json  the matching tokenizer
//
// Both or neither. A model with the wrong tokenizer produces token ids that mean
// something else and scores that look plausible, which is the worst failure available
// here, so the pairing is by filename and not configurable.
func openZeroShot(dir, prefer string) (ZeroShot, error) {
	modelPath := filepath.Join(dir, "zeroshot.onnx")
	tokPath := filepath.Join(dir, "zeroshot.tokenizer.json")
	if _, err := os.Stat(modelPath); err != nil {
		return nil, nil // not an error: no model is the normal state
	}
	if _, err := os.Stat(tokPath); err != nil {
		return nil, fmt.Errorf("%s exists but %s does not; a model without its tokenizer cannot be used", modelPath, tokPath)
	}

	initONNX.Do(func() {
		if p := os.Getenv("ONNXRUNTIME_LIB"); p != "" {
			ort.SetSharedLibraryPath(p)
		}
		initErr = ort.InitializeEnvironment()
	})
	if initErr != nil {
		return nil, fmt.Errorf("initialising onnxruntime: %w", initErr)
	}

	tok, err := tokenizers.FromFile(tokPath)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", tokPath, err)
	}

	opts, err := ort.NewSessionOptions()
	if err != nil {
		tok.Close()
		return nil, err
	}
	defer opts.Destroy()

	// Threading and optimisation, set explicitly.
	//
	// Not defaults worth trusting. ONNX Runtime sizes its thread pool from what it
	// can see of the machine, and inside a container that is routinely wrong — it
	// reads the host's core count and then runs against a cgroup quota, or reads one
	// core and leaves fifteen idle. Either way the number it picks has nothing to do
	// with what this process is allowed to use.
	//
	// One inference here is a batch of one row per candidate label, so it
	// parallelises well and the intra-op pool is what matters. Inter-op is left at
	// one: there is a single graph and nothing to overlap, and a second pool only
	// competes with the first for the same cores.
	threads := runtime.GOMAXPROCS(0)
	if n := os.Getenv("LAZARET_ML_THREADS"); n != "" {
		if parsed, err := strconv.Atoi(n); err == nil && parsed > 0 {
			threads = parsed
		}
	}
	if err := opts.SetIntraOpNumThreads(threads); err != nil {
		log.Printf("lazaret-ml: could not set inference threads: %v", err)
	}
	if err := opts.SetInterOpNumThreads(1); err != nil {
		log.Printf("lazaret-ml: could not set inter-op threads: %v", err)
	}
	if err := opts.SetGraphOptimizationLevel(ort.GraphOptimizationLevelEnableAll); err != nil {
		log.Printf("lazaret-ml: could not set graph optimisation: %v", err)
	}
	// The shapes here repeat — same label count, similar lengths — so letting the
	// runtime plan its allocations once is worth the memory it holds onto.
	_ = opts.SetMemPattern(true)
	_ = opts.SetCpuMemArena(true)
	log.Printf("lazaret-ml: inference threads: %d", threads)

	acc := applyAccelerators(opts, prefer)
	setActiveBackend(acc.Provider)
	log.Printf("lazaret-ml: inference on %s%s", acc.Provider,
		map[bool]string{true: " — " + acc.Detail, false: ""}[acc.Detail != ""])

	s, err := ort.NewDynamicAdvancedSession(modelPath,
		[]string{"input_ids", "attention_mask"}, []string{"logits"}, opts)
	if err != nil {
		tok.Close()
		return nil, fmt.Errorf("loading %s: %w", modelPath, err)
	}

	z := &onnxZeroShot{tok: tok, session: s, cls: 1, sep: 2, pad: 0, maxLen: 384, accel: acc}
	if err := z.calibrateSpecials(); err != nil {
		z.Close()
		return nil, err
	}
	return z, nil
}

// calibrateSpecials recovers the special token ids from the tokenizer rather than
// trusting the values above.
//
// They are the DeBERTa-v3 defaults, and a BERT-family tokenizer uses different ones
// ([CLS] 101, [SEP] 102). Getting them wrong does not fail: it produces a sequence the
// model happily scores and whose scores mean nothing.
func (z *onnxZeroShot) calibrateSpecials() error {
	withSpecial, _ := z.tok.Encode("a", true)
	without, _ := z.tok.Encode("a", false)
	if len(withSpecial) != len(without)+2 {
		return fmt.Errorf("tokenizer adds %d special tokens around a single word; expected 2 (a leading classifier token and a trailing separator)",
			len(withSpecial)-len(without))
	}
	z.cls = withSpecial[0]
	z.sep = withSpecial[len(withSpecial)-1]
	return nil
}

// Accelerator reports what the inference is actually running on.
func (z *onnxZeroShot) Accelerator() accelerator { return z.accel }

func (z *onnxZeroShot) Close() error {
	if z.session != nil {
		z.session.Destroy()
	}
	if z.tok != nil {
		z.tok.Close()
	}
	return nil
}

// Score runs one batch: every label against the same text.
func (z *onnxZeroShot) Score(ctx context.Context, text string, labels []Label) (map[string]float64, error) {
	if len(labels) == 0 {
		return map[string]float64{}, nil
	}

	premise, _ := z.tok.Encode(text, false)

	rows := make([][]uint32, len(labels))
	longest := 0
	for i, l := range labels {
		hyp, _ := z.tok.Encode("This text is "+l.Hypothesis+".", false)
		// Truncate the premise, never the hypothesis: a half-read email still
		// entails or does not, while a half-read hypothesis asks a different
		// question. Head rather than tail, because the ask in a phishing message is
		// at the top and the quoted thread is at the bottom.
		room := z.maxLen - 3 - len(hyp)
		if room < 16 {
			return nil, fmt.Errorf("label %q leaves no room for the text in a %d-token window", l.Name, z.maxLen)
		}
		p := premise
		if len(p) > room {
			p = p[:room]
		}
		row := make([]uint32, 0, len(p)+len(hyp)+3)
		row = append(row, z.cls)
		row = append(row, p...)
		row = append(row, z.sep)
		row = append(row, hyp...)
		row = append(row, z.sep)
		rows[i] = row
		if len(row) > longest {
			longest = len(row)
		}
	}

	batch := int64(len(rows))
	seq := int64(bucketSeq(longest, z.maxLen))
	ids := make([]int64, batch*seq)
	mask := make([]int64, batch*seq)
	for i, row := range rows {
		base := int64(i) * seq
		if int64(len(row)) > seq {
			row = row[:seq]
		}
		for j := range row {
			ids[base+int64(j)] = int64(row[j])
			mask[base+int64(j)] = 1
		}
		for j := len(row); int64(j) < seq; j++ {
			ids[base+int64(j)] = int64(z.pad)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	shape := ort.NewShape(batch, seq)
	inIDs, err := ort.NewTensor(shape, ids)
	if err != nil {
		return nil, err
	}
	defer inIDs.Destroy()
	inMask, err := ort.NewTensor(shape, mask)
	if err != nil {
		return nil, err
	}
	defer inMask.Destroy()

	z.mu.Lock()
	defer z.mu.Unlock()

	out, err := ort.NewEmptyTensor[float32](ort.NewShape(batch, int64(z.classes())))
	if err != nil {
		return nil, err
	}
	defer out.Destroy()

	if err := z.session.Run([]ort.Value{inIDs, inMask}, []ort.Value{out}); err != nil {
		return nil, fmt.Errorf("inference: %w", err)
	}

	logits := out.GetData()
	n := z.classes()
	scores := make(map[string]float64, len(labels))
	for i, l := range labels {
		row := logits[i*n : (i+1)*n]
		scores[l.Name] = entailment(row)
	}
	return scores, nil
}

// classes is the width of the model's output.
//
// Two shapes are in use. A binary head is {entailment, not_entailment}; the three-way
// MNLI head is {entailment, neutral, contradiction}. Both are read the same way here —
// entailment against the largest of the rest — so the only thing that must be right is
// the width, and it is fixed at two because that is what the zeroshot-v2 models export.
func (z *onnxZeroShot) classes() int { return 2 }

// entailment turns the head's logits into a probability.
func entailment(row []float32) float64 {
	best := math.Inf(-1)
	for _, v := range row {
		if float64(v) > best {
			best = float64(v)
		}
	}
	sum := 0.0
	for _, v := range row {
		sum += math.Exp(float64(v) - best)
	}
	if sum == 0 {
		return 0
	}
	return math.Exp(float64(row[0])-best) / sum
}

// seqBuckets are the sequence lengths a batch is padded to.
//
// The reason is compilation, not arithmetic. A graph compiler — MIGraphX on AMD,
// TensorRT on NVIDIA — compiles per input shape and caches the result, so a batch
// padded to its own exact length presents a new shape for almost every message and
// pays the compile every time. Measured on an RX 9060 XT: the first call took two
// minutes, the second seventy-six seconds, and once a shape was cached the same
// inference took a quarter of a second.
//
// Rounding up to a handful of lengths turns "a compile per message" into "a compile
// per bucket, once". Three buckets rather than one because the CPU path pays for
// every padded token it computes, and always padding a short message to the longest
// window would triple its cost on a deployment with no GPU.
var seqBuckets = []int{128, 256, 384}

// bucketSeq rounds a length up to the next bucket, or to the window if it exceeds
// them all.
func bucketSeq(longest, maxLen int) int {
	for _, b := range seqBuckets {
		if b >= longest && b <= maxLen {
			return b
		}
	}
	return maxLen
}
