# SPDX-License-Identifier: AGPL-3.0-only
#
# The Garage CLI with a shell around it.
#
# The official image is distroless and has no shell, so the bootstrap cannot run
# inside it, and running the CLI from the host would need a docker socket. This
# copies the one binary onto Alpine: same version, no extra download, and the
# bootstrap is an ordinary script we can read.
FROM dxflrs/garage:v1.0.1 AS garage

FROM alpine:3.21
COPY --from=garage /garage /usr/local/bin/garage
COPY bootstrap.sh /usr/local/bin/bootstrap.sh
RUN chmod +x /usr/local/bin/bootstrap.sh
ENTRYPOINT ["/usr/local/bin/bootstrap.sh"]
