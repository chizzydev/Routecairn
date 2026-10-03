# Build the pinned community source; legacy minio/minio registry tags may be unavailable.
FROM golang:1.25.1-bookworm AS build
RUN GOBIN=/out go install -trimpath github.com/minio/minio@v0.0.0-20250907161309-07c3a429bfed
RUN cp /go/pkg/mod/github.com/minio/minio@v0.0.0-20250907161309-07c3a429bfed/LICENSE /out/LICENSE

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && mkdir /data && chown 1000:1000 /data
COPY --from=build /out/minio /usr/local/bin/minio
COPY --from=build /out/LICENSE /usr/share/doc/minio/LICENSE
USER 1000:1000
EXPOSE 9000
ENTRYPOINT ["minio"]
CMD ["server","/data"]
HEALTHCHECK --interval=5s --timeout=5s --retries=20 CMD ["curl","-fsS","http://127.0.0.1:9000/minio/health/ready"]
