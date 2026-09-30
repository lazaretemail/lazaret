# SPDX-License-Identifier: AGPL-3.0-only
#
# Lightpanda, used as the browser that visits links.
#
# Not a replacement for the Chromium that screenshots messages, and cannot be: it does
# not paint at all. A screenshot from it comes back as a placeholder, which would feed
# OCR a blank and have every rule downstream report "found nothing" rather than "could
# not look". See services/render/linkbrowser.go.
#
# The link path is the opposite case. It asks a browser for the document after script
# has run and derives inner_text, display_text and links from that string in Go — no
# layout is read, no pixels are painted, no fonts are used. Not painting is the whole
# point of this engine, so the one job it cannot do is the one we are not asking of it.
FROM debian:bookworm-slim

# Pinned, with the checksum of the binary this was measured against. A browser that
# visits attacker-chosen URLs should move when someone decides it moves.
ARG LIGHTPANDA_VERSION=0.4.1
ARG LIGHTPANDA_SHA256=1d40801e72c0bc61b2cbd3f3562bcfc46de7b79e0568f33f686b64f2e587610a

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /usr/local/bin/lightpanda \
      "https://github.com/lightpanda-io/browser/releases/download/${LIGHTPANDA_VERSION}/lightpanda-x86_64-linux" \
 && echo "${LIGHTPANDA_SHA256}  /usr/local/bin/lightpanda" | sha256sum -c - \
 && chmod +x /usr/local/bin/lightpanda \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10003 lightpanda
USER lightpanda
WORKDIR /home/lightpanda

EXPOSE 9222

# Its CDP port carries no authentication, so it must not be on a network anything else
# can reach — the compose file puts it on one with a single other member. That is the
# same posture our own Chromium has, which listens on loopback inside its container.
ENTRYPOINT ["/usr/local/bin/lightpanda", "serve", "--host", "0.0.0.0", "--port", "9222"]
