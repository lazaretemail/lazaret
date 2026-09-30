#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fetch the entailment model lazaret-ml uses for intents, topics and tags.
#
# A script rather than something the service does on its own, because downloading
# model weights is a licensing decision and an egress decision, and neither should
# happen because a container started.
#
# The default is MoritzLaurer/deberta-v3-base-zeroshot-v2.0 — MIT licensed, and
# deliberately trained on commercially usable data, which is what the "v2.0" in the
# name refers to. Check the model card yourself before deploying it; the licence of
# the weights is independent of the licence of this code.
#
#   ./fetch-models.sh /var/lib/lazaret/models
#
set -eu

DIR="${1:-./models}"
MODEL="${LAZARET_ZEROSHOT_MODEL:-MoritzLaurer/deberta-v3-base-zeroshot-v2.0}"
BASE="https://huggingface.co/${MODEL}/resolve/main"

echo "model:       $MODEL"
echo "destination: $DIR"
echo

mkdir -p "$DIR"

# The two files are a pair. A model with the wrong tokenizer produces token ids that
# mean something else and scores that look entirely plausible, so they are fetched
# together and named after what they are rather than after a capability — one model
# answers intents, topics and tags.
fetch() {
    url="$1"; out="$2"
    echo "fetching $(basename "$out") ..."
    # To a temporary name first: an interrupted download that left a half-written
    # zeroshot.onnx in place would be loaded on the next start.
    curl -fL --progress-bar -o "$out.part" "$url"
    mv "$out.part" "$out"
}

fetch "$BASE/onnx/model.onnx"   "$DIR/zeroshot.onnx"
fetch "$BASE/tokenizer.json"    "$DIR/zeroshot.tokenizer.json"

echo
echo "done. Start the service built with -tags onnx and pointed at $DIR."
echo
echo "The logo reference pack is not fetched: it is other companies' trademarks, and"
echo "whether to redistribute them is a decision for whoever deploys this. Without it,"
echo "brand detection still reads wordmarks out of OCR text, which covers most of the"
echo "brands the rule corpus asks about."
