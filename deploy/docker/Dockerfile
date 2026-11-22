# Ubuntu/Linux Docker lab: dashboard and Go mTLS service, not endpoint agents.
FROM node:22-bookworm AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.25-bookworm AS backend
ARG SOURCE_SHA=uncommitted
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/socgateway ./cmd/socgateway
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.sourceSHA=${SOURCE_SHA} -X main.version=docker-lab" -o /out/edrd ./cmd/edrd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=backend /out/edrd /usr/local/bin/edrd
COPY --from=backend /out/socgateway /usr/local/bin/socgateway
COPY --from=ui /src/frontend/dist/ /opt/turansec/web/
USER root
ENTRYPOINT ["/usr/local/bin/edrd","--config","/etc/turansec/edrd.json"]
