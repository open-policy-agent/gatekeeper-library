FROM golang:1.23@sha256:613a108a4a4b1dfb6923305db791a19d088f77632317cfc3446825c54fb862cd

ARG GOMPLATE_VERSION

# Install gomplate
RUN go install github.com/hairyhenderson/gomplate/v3/cmd/gomplate@v${GOMPLATE_VERSION}

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/bash"]
