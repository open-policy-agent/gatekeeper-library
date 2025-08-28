FROM golang:1.25@sha256:91e2cd436f7adbfad0a0cbb7bf8502fa863ed8461414ceebe36c6304731e0fd9

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
