# Release image for netbird-signal, built by GoReleaser (dockers_v2) from
# .goreleaser.fork.yaml. The build context contains <os>/<arch>/netbird-signal
# plus the files listed in extra_files — the source tree is NOT part of the
# context.
# The binary is pure Go (CGO_ENABLED=0), so the distroless static base is
# enough; it ships ca-certificates and tzdata. The nonroot tag sets USER 65532:
# the signal server is stateless and needs no writable path.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# TARGETPLATFORM is a buildx predefined ARG. It must be re-declared inside the
# stage: a global ARG (before FROM) is not in scope for instructions after FROM.
ARG TARGETPLATFORM

COPY $TARGETPLATFORM/netbird-signal /go/bin/netbird-signal
COPY NOTICE LICENSE /usr/share/doc/netbird/
COPY LICENSES /usr/share/doc/netbird/LICENSES/
COPY third_party_licenses /usr/share/doc/netbird/third_party_licenses/

ENTRYPOINT [ "/go/bin/netbird-signal", "run" ]
CMD ["--log-file", "console"]
