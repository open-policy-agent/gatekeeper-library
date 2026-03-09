FROM golang:1.26@sha256:e2ddb153f786ee6210bf8c40f7f35490b3ff7d38be70d1a0d358ba64225f6428

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
