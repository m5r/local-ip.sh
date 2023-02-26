FROM golang:1.19-alpine AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /app/local-ip

FROM gcr.io/distroless/base-debian11

ENV PORT 53

WORKDIR /

COPY --from=build /app/local-ip /
COPY ./.lego /.lego

EXPOSE $PORT
USER root

CMD ["/local-ip"]