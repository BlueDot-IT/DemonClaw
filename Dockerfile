FROM rust:1.98-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/demonclaw --create-home \
         --shell /usr/sbin/nologin demonclaw

WORKDIR /app
COPY --from=builder /src/target/release/demonclaw /usr/local/bin/demonclaw
COPY --from=builder /src/templates /app/templates
COPY --from=builder /src/migrations /app/migrations

USER demonclaw
EXPOSE 3000
ENTRYPOINT ["demonclaw"]
CMD ["run"]
