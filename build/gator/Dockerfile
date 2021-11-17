FROM alpine

# Install dependencies. libc6-compat is for CGO support.
RUN apk --no-cache add curl tar libc6-compat

# Download and unpack gator
WORKDIR /bin
RUN curl -OL https://github.com/open-policy-agent/gatekeeper/releases/download/v3.7.0/gator-v3.7.0-linux-amd64.tar.gz
RUN tar xvf gator-v3.7.0-linux-amd64.tar.gz && rm gator-v3.7.0-linux-amd64.tar.gz

# Create the mount point for the library
RUN mkdir /gatekeeper-library
WORKDIR /gatekeeper-library

ENTRYPOINT ["/bin/gator"]
