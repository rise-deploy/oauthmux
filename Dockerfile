# syntax=docker/dockerfile:1.7
FROM --platform=$TARGETPLATFORM rust:1.97.1-bookworm AS build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends musl-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN case "$(uname -m)" in \
      x86_64) target=x86_64-unknown-linux-musl ;; \
      aarch64) target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac \
    && rustup target add "$target" \
    && cargo build --locked --release --target "$target" -p oauthmux \
    && cp "target/$target/release/oauthmux" /oauthmux

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /oauthmux /oauthmux
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/oauthmux"]
