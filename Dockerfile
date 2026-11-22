FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build

FROM gcr.io/distroless/static-debian13@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383

WORKDIR /local-ip

COPY --from=build /app/local-ip.sh /local-ip/local-ip.sh

VOLUME /local-ip/state

#      DNS           HTTP   HTTPS
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

# Root binds ports 53, 80 and 443 and owns the state volume, which earlier versions wrote as root; the machine runs nothing else.
USER root

CMD ["/local-ip/local-ip.sh"]
