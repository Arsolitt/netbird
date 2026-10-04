# Release image for netbird-mgmt, built by GoReleaser (dockers_v2) from
# .goreleaser.fork.yaml. The binary is already compiled per platform, so the
# build context contains <os>/<arch>/netbird-mgmt plus the files listed in
# extra_files — the source tree is NOT part of the context.
# Base digest-pinned; runs as root like the upstream management image so
# deployments with root-owned volumes (store, Let's Encrypt) keep working.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

RUN apt update && apt install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# TARGETPLATFORM is a buildx predefined ARG. It must be re-declared inside the
# stage: a global ARG (before FROM) is not in scope for instructions after FROM.
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/netbird-mgmt /go/bin/netbird-mgmt
COPY NOTICE LICENSE /usr/share/doc/netbird/
COPY LICENSES /usr/share/doc/netbird/LICENSES/
COPY third_party_licenses /usr/share/doc/netbird/third_party_licenses/

ENTRYPOINT [ "/go/bin/netbird-mgmt", "management" ]
CMD ["--log-file", "console"]
