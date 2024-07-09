FROM golang:1.21-alpine AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /app/local-ip

FROM gcr.io/distroless/base-debian12:latest

ENV PORT 53

WORKDIR /app

COPY --from=build /app/local-ip /app/local-ip
COPY --from=build /app/http/static /app/http/static
COPY ./.lego /app/.lego

EXPOSE $PORT
USER root

CMD ["/app/local-ip"]
