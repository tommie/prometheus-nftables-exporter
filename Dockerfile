FROM golang:alpine AS go_builder

RUN apk --no-cache add git libcap

WORKDIR /go/src/app
COPY ./ ./

RUN go get ./...
RUN go install ./cmd/promnftd
RUN setcap -q cap_net_admin,cap_net_raw+ep promnftd


FROM alpine:latest

RUN apk --no-cache add libc6-compat

COPY --from=go_builder /go/src/app/promnftd /usr/local/bin/

# Port 9732 is what https://github.com/Intrinsec/nftables_exporter/blob/master/Dockerfile uses.
ARG promnftd_user=nobody
USER $promnftd_user

ENTRYPOINT ["promnftd"]
CMD ["-http-addr", "localhost:9732"]
EXPOSE 9732
