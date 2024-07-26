FROM golang:1.22-alpine AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN go build

FROM gcr.io/distroless/base-debian12:latest

WORKDIR /local-ip

COPY --from=build /app/local-ip.sh /local-ip/local-ip.sh
COPY --from=build /app/http/static /local-ip/http/static

VOLUME /local-ip/.lego

#      DNS    HTTP   HTTPS
EXPOSE 53/udp 80/tcp 443/tcp

USER root

CMD ["/local-ip/local-ip.sh"]
