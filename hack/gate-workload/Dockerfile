FROM scratch
ENV GODEBUG=multipathtcp=0
COPY gate-server /gate-server
EXPOSE 8080
ENTRYPOINT ["/gate-server"]
