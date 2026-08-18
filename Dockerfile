FROM golang:1.21-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git build-base

# Build Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/gf@latest

# Main image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    whatweb \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from builder
COPY --from=builder /go/bin/subfinder /usr/bin/subfinder
COPY --from=builder /go/bin/httpx /usr/bin/httpx
COPY --from=builder /go/bin/katana /usr/bin/katana
COPY --from=builder /go/bin/gf /usr/bin/gf

# Set up the Python application
WORKDIR /app
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Set entrypoint
ENTRYPOINT ["hb-recon"]
CMD ["-h"]
