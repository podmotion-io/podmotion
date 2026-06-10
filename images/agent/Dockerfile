FROM gcr.io/distroless/static:nonroot
COPY bin/agent-linux-amd64 /agent
USER 65532:65532
ENTRYPOINT ["/agent"]
