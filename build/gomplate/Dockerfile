FROM golang:1.25@sha256:6ca9eb0b32a4bd4e8c98a4a2edf2d7c96f3ea6db6eb4fc254eef6c067cf73bb4

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
