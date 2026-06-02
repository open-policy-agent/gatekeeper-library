FROM golang:1.26@sha256:98fc714bfe32e7d3c539d63bda9b9cd089fd699dc3cbd1c534fec3c4deb9ca98

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
