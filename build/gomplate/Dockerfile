FROM golang:1.27@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
