FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
# The release tag, for the build_info metric.
ARG VERSION=
# The commit it was built from.
ARG REVISION=
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.buildVersion=$VERSION -X main.buildRevision=$REVISION" -o /out/yapnest-relay .

# no RUN here: this stage is the target platform's. alpine already has the CA bundle (ca-certificates-bundle),
# which the APNs connection needs. Nothing listens unless the deploy sets RELAY_METRICS_ADDR, which is why no port is exposed here: the relay
# dials the XMPP server and Apple.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=build /out/yapnest-relay /yapnest-relay
USER 65534:65534
ENTRYPOINT ["/yapnest-relay"]
