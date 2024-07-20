FROM golang:1.22-alpine AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN go build -o /app/local-ip

FROM gcr.io/distroless/base-debian12:latest

WORKDIR /local-ip

COPY --from=build /app/local-ip /local-ip/local-ip
COPY --from=build /app/http/static /local-ip/http/static

VOLUME /local-ip/.lego

# DNS
EXPOSE 53/udp
# HTTP
EXPOSE 80/tcp
# HTTPS
EXPOSE 443/tcp

USER root

CMD ["/local-ip/local-ip"]
