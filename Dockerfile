FROM golang:1.24.5-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o quasar-gateway ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -g 1001 -S quasar && \
    adduser -S -D -H -u 1001 -s /sbin/nologin -G quasar quasar

WORKDIR /app

COPY --from=builder /app/quasar-gateway .

RUN chown -R quasar:quasar /app
USER quasar

EXPOSE 8080 8081

CMD ["./quasar-gateway"]