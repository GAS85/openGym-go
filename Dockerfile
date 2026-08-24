# Frontend Build
FROM --platform=$BUILDPLATFORM node:22-alpine AS fe-build
WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci 2>/dev/null || npm install

COPY frontend/ ./
RUN npm run build

### Backend Build

FROM golang:1.26-alpine AS be-build

WORKDIR /build

COPY app/ ./

RUN go mod download
RUN go build -o opengym-go .

### Final Container

FROM nginx:alpine

ARG VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=unknown

LABEL maintainer="Georgiy Sitnikov https://github.com/GAS85" \
    org.opencontainers.image.title="opengym-go" \
    org.opencontainers.image.description="Self-hosted OpenGym port & body-weight tracker — plan routines, log workouts (supersets & cardio too), track your weight and progress, passkey login. Your data, your server." \
    org.opencontainers.image.source="https://github.com/GAS85/openGym-go" \
    org.opencontainers.image.url="https://hub.docker.com/r/gas85/opengym-go" \
    org.opencontainers.image.documentation="https://github.com/GAS85/openGym-go#readme" \
    org.opencontainers.image.licenses="AGPL-3.0-or-later" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE

COPY web/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --chmod=555 web/35-assets-download.sh /docker-entrypoint.d/35-assets-download.sh
COPY --chmod=555 web/40-backend-start.sh /docker-entrypoint.d/40-backend-start.sh

# Add Frontend
COPY --from=fe-build /app/dist /usr/share/nginx/html

# Add Backend
COPY --from=be-build /build/opengym-go /app/opengym-go

# exercise media (img/gif) is mounted at runtime from the media volume. But needs to be created prior
RUN mkdir /usr/share/nginx/html/img /usr/share/nginx/html/gif /data

# Set Default ENVs for nginx
ENV NGINX_PORT=80
ENV BACKEND=localhost
ENV PORT=3000

HEALTHCHECK --interval=5m \
            --timeout=5s \
            --retries=3 \
            CMD wget --spider -q "http://127.0.0.1:${NGINX_PORT}/api/config" -U docker-healthcheck || exit 1
