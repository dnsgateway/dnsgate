# syntax = docker/dockerfile:1.28
########################################

FROM --platform=${TARGETARCH} scratch AS gorelease

COPY --from=gcr.io/distroless/static-debian13:nonroot . .
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/dnsgate /bin/dnsgate

ENV DNSGATE_LISTEN_ADDRESS=:8443
ENTRYPOINT ["/bin/dnsgate"]

########################################

FROM --platform=${TARGETARCH} scratch AS gorelease-acme

COPY --from=gcr.io/distroless/static-debian13:nonroot . .
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/dnsgate-acme /bin/dnsgate-acme

ENV DNSGATE_ACME_LISTEN_ADDRESS=:8080
ENTRYPOINT ["/bin/dnsgate-acme"]
