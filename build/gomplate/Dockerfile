FROM golang:1.22@sha256:2bd56f00ff47baf33e64eae7996b65846c7cb5e0a46e0a882ef179fd89654afa

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
