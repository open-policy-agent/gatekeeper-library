FROM golang:1.22@sha256:fcae9e0e7313c6467a7c6632ebb5e5fab99bd39bd5eb6ee34a211353e647827a

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
