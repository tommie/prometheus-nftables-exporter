ARG golang_ver=1.18
FROM golang:$golang_ver-alpine AS go_builder

RUN apk --no-cache add git libcap

WORKDIR /go/src/app
COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./
RUN go build ./cmd/promnftd
RUN setcap cap_net_admin,cap_net_raw+ep promnftd

FROM alpine:latest

RUN apk --no-cache add libc6-compat libcap

COPY --from=go_builder /go/src/app/promnftd /usr/local/bin/

# https://github.com/moby/moby/issues/35699
RUN setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/promnftd && \
    apk --no-cache del libcap

# Port 9732 is what https://github.com/Intrinsec/nftables_exporter/blob/master/Dockerfile uses.
ARG promnftd_user=nobody
USER $promnftd_user

ENTRYPOINT ["promnftd"]
CMD ["-http-addr", "localhost:9732"]
EXPOSE 9732
