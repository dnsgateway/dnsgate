# syntax = docker/dockerfile:1.28
########################################

FROM --platform=${TARGETARCH} scratch AS gorelease

COPY --from=gcr.io/distroless/static-debian13:nonroot . .
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/dnsgate /bin/dnsgate

ENV LISTEN_ADDRESS=:8443
ENTRYPOINT ["/bin/dnsgate"]
