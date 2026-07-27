FROM gcr.io/distroless/static:nonroot
# Build-provenance stamp: the git commit this image was built from.
# Defaults to "unknown" so a build without git available still succeeds.
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.revision=$GIT_SHA
COPY bin/scheduler-linux-amd64 /scheduler
USER 65532:65532
ENTRYPOINT ["/scheduler"]
