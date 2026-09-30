// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// The learned model, as an operator interacts with it.
//
// Training is explicit. It could run on a timer, and probably should once a
// deployment is settled, but a model that silently retrains is one whose behaviour
// changes without anybody deciding it should — and the first time that matters is
// the day a run of unusual reviews teaches it something wrong.

// modelCache holds the current model in memory, because it is read on every ingest.
type modelCache struct {
	mu    sync.RWMutex
	model *Model
}

func (c *modelCache) get() *Model {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.model
}

func (c *modelCache) set(m *Model) {
	c.mu.Lock()
	c.model = m
	c.mu.Unlock()
}

// loadModel reads the stored model at startup.
func (a *API) loadModel(ctx context.Context, tenant string) {
	raw, err := a.store.LatestModel(ctx, tenant)
	if err != nil || len(raw) == 0 {
		return
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Printf("learned model: stored weights do not parse: %v", err)
		return
	}
	a.pipeline.model.set(&m)
	log.Printf("learned model: version %d, trained on %d reviews, %.0f%% accurate against a %.0f%% baseline",
		m.Version, m.Examples, m.Accuracy*100, m.Baseline*100)
}

// trainModel fits a new model from the reviews recorded so far.
func (a *API) trainModel(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	reviewed, err := a.store.ReviewedMessages(ctx, tenant, 0)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	examples := make([]Example, 0, len(reviewed))
	for _, rm := range reviewed {
		var an StoredAnalysis
		if err := json.Unmarshal(rm.Analysis, &an); err != nil {
			continue
		}
		label := LabelGood
		if rm.Bad {
			label = LabelBad
		}
		// Features come from the stored analysis, which is what the system
		// believed when the analyst was looking at it. Recomputing them now would
		// train today's rules against yesterday's decisions.
		examples = append(examples, Example{
			MessageID: rm.MessageID,
			Features:  FeaturesFor(&an, Summary{}, an.Sender),
			Label:     label,
		})
	}

	m, err := Train(examples, 0.01, 400)
	if err != nil {
		// A refusal, not a failure: not enough reviews yet is the normal state of a
		// new deployment and the message says what is missing.
		fail(w, http.StatusUnprocessableEntity, err)
		return
	}
	m.TrainedAt = time.Now().UTC().Format(time.RFC3339)

	// The version is reserved before marshalling, so it is inside the stored
	// weights rather than only in the row — otherwise a restart loads a model that
	// calls itself version zero.
	version, err := a.store.NextModelVersion(ctx, tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	m.Version = version

	blob, err := json.Marshal(m)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.store.SaveModel(ctx, tenant, version, blob); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	a.pipeline.model.set(m)

	log.Printf("learned model: trained version %d on %d reviews (%d confirmed, %d dismissed), "+
		"%.0f%% accurate against a %.0f%% baseline",
		version, m.Examples, m.Bad, m.Good, m.Accuracy*100, m.Baseline*100)

	writeJSON(w, http.StatusOK, modelReport(m))
}

// describeModel is the read side: what the model knows, for a page that lets an
// administrator disagree with it.
func (a *API) describeModel(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	m := a.pipeline.model.get()
	if m == nil {
		// How far off training is, so the page can say "23 more reviews" rather
		// than "no model".
		reviewed, _ := a.store.ReviewedMessages(ctx, tenant, 0)
		bad, good := 0, 0
		for _, rm := range reviewed {
			if rm.Bad {
				bad++
			} else {
				good++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"trained":       false,
			"reviews":       bad + good,
			"confirmed":     bad,
			"dismissed":     good,
			"need_total":    MinExamples,
			"need_per_side": MinPerClass,
		})
		return
	}
	writeJSON(w, http.StatusOK, modelReport(m))
}

func modelReport(m *Model) map[string]any {
	return map[string]any{
		"trained":    true,
		"useful":     m.Useful(),
		"version":    m.Version,
		"trained_at": m.TrainedAt,
		"reviews":    m.Examples,
		"confirmed":  m.Bad,
		"dismissed":  m.Good,
		"accuracy":   m.Accuracy,
		"baseline":   m.Baseline,
		"top":        m.Top(30),
	}
}

// forgetModel discards every learned model for a tenant.
//
// Needed, and not only for tidiness. A model is trained on people's judgements about
// their own mail, and an administrator who decides it has learned something wrong —
// or who simply does not want it — has to be able to remove it rather than wait for
// it to be outvoted.
func (a *API) forgetModel(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	if err := a.store.ForgetModels(store.WithTenant(r.Context(), tenant), tenant); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	a.pipeline.model.set(nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "forgotten"})
}
