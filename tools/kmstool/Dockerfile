# syntax=docker/dockerfile:1

# kmstool_enclave_cli, built for the Node Alpine runtime.
#
# TOOLCHAIN PIN — do not casually bump the builder image.
#   The AWS CRT pins below are the dependency profile AWS uses for
#   aws-nitro-enclaves-sdk-c v0.4.5. They build most predictably on a
#   period-compatible Alpine toolchain. The builder is pinned to alpine:3.20
#   while the runtime remains node:24-alpine.
#
# LINKING
#   The AWS CRT/json/aws-lc/s2n dependencies are built statically into the
#   kmstool_enclave_cli binary. libnsm.so remains a shared library, matching
#   the upstream NSM build. The final ldd check is the source of truth for
#   remaining Alpine runtime library requirements.
#
# VALIDATION
#   Docker build validation checks ELF format and shared-library resolution.
#   kmstool_enclave_cli itself requires NSM during process startup, so command
#   execution must be validated inside a running Nitro Enclave.

FROM alpine:3.20 AS kmstool-builder

ENV AWS_NE_SDK_C_VERSION="v0.4.5" \
  AWS_NE_SDK_C_COMMIT="cd61b6187c8b20867ba4368d1ae62c5790c0269a" \
  AWS_LC_VERSION="v1.12.0" \
  AWS_LC_COMMIT="cb7712dfa896d32d55992e2cb13d5fa54fb77002" \
  AWS_S2N_TLS_VERSION="v1.3.46" \
  AWS_S2N_TLS_COMMIT="e954ee5dc878c5c343d35574e7d07246a1e59314" \
  AWS_C_COMMON_VERSION="v0.8.0" \
  AWS_C_COMMON_COMMIT="be35e65a6c67ae2ffd126516c9783ac1dd2e8910" \
  AWS_C_SDKUTILS_VERSION="v0.1.2" \
  AWS_C_SDKUTILS_COMMIT="e3c23f4aca31d9e66df25827645f72cbcbfb657a" \
  AWS_C_CAL_VERSION="v0.5.18" \
  AWS_C_CAL_COMMIT="1458c70a26877345ca28e333a092096afd410774" \
  AWS_C_IO_VERSION="v0.11.0" \
  AWS_C_IO_COMMIT="8f4508f5ec7d2949d5545e2b1ddcd1beb47a76a8" \
  AWS_C_COMPRESSION_VERSION="v0.2.14" \
  AWS_C_COMPRESSION_COMMIT="5fab8bc5ab5321d86f6d153b06062419080820ec" \
  AWS_C_HTTP_VERSION="v0.7.6" \
  AWS_C_HTTP_COMMIT="0600662610aa871a11aebe6ed67a11997317cbef" \
  AWS_C_AUTH_VERSION="v0.6.15" \
  AWS_C_AUTH_COMMIT="831fa583b83574db29cbae139b42e0d7a1d1ebb8" \
  JSON_C_VERSION="json-c-0.16-20220414" \
  JSON_C_COMMIT="2f2ddc1f2dbca56c874e8f9c31b5b963202d80e7" \
  AWS_NE_NSM_API_VERSION="v0.4.0" \
  AWS_NE_NSM_API_COMMIT="4b851f3006c6fa98f23dcffb2cba03b39de9b8af" \
  RUST_TOOLCHAIN_VERSION="1.92" \
  RUSTUP_VERSION="1.28.2" \
  RUSTUP_INIT_SHA256="e6599a1c7be58a2d8eaca66a80e0dc006d87bbcf780a58b7343d6e14c1605cb2" \
  RUSTFLAGS="-C target-feature=-crt-static"

RUN apk add --no-cache \
  bash \
  ca-certificates \
  cmake \
  curl \
  file \
  g++ \
  gcc \
  git \
  go \
  linux-headers \
  make \
  ninja \
  perl \
  pkgconf \
  tar

RUN ln -s /usr/lib /usr/lib64 || true

RUN go env -w GOPROXY=direct

WORKDIR /build

RUN mkdir -p /out && cat > /out/kmstool-build-versions.txt <<EOF_VERSIONS
kmstool_enclave_cli:
  aws-nitro-enclaves-sdk-c=${AWS_NE_SDK_C_VERSION}

build libraries:
  aws-lc=${AWS_LC_VERSION}
  s2n-tls=${AWS_S2N_TLS_VERSION}
  aws-c-common=${AWS_C_COMMON_VERSION}
  aws-c-sdkutils=${AWS_C_SDKUTILS_VERSION}
  aws-c-cal=${AWS_C_CAL_VERSION}
  aws-c-io=${AWS_C_IO_VERSION}
  aws-c-compression=${AWS_C_COMPRESSION_VERSION}
  aws-c-http=${AWS_C_HTTP_VERSION}
  aws-c-auth=${AWS_C_AUTH_VERSION}
  json-c=${JSON_C_VERSION}
  aws-nitro-enclaves-nsm-api=${AWS_NE_NSM_API_VERSION}
  rust=${RUST_TOOLCHAIN_VERSION}
  builder=alpine:3.20
EOF_VERSIONS

RUN git clone --depth 1 --branch "${AWS_LC_VERSION}" https://github.com/awslabs/aws-lc.git \
  && test "$(git -C aws-lc rev-parse HEAD)" = "${AWS_LC_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-lc \
  -B aws-lc/build \
  && cmake --build aws-lc/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_S2N_TLS_VERSION}" https://github.com/aws/s2n-tls.git \
  && test "$(git -C s2n-tls rev-parse HEAD)" = "${AWS_S2N_TLS_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S s2n-tls \
  -B s2n-tls/build \
  && cmake --build s2n-tls/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_COMMON_VERSION}" https://github.com/awslabs/aws-c-common.git \
  && test "$(git -C aws-c-common rev-parse HEAD)" = "${AWS_C_COMMON_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-common \
  -B aws-c-common/build \
  && cmake --build aws-c-common/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_SDKUTILS_VERSION}" https://github.com/awslabs/aws-c-sdkutils.git \
  && test "$(git -C aws-c-sdkutils rev-parse HEAD)" = "${AWS_C_SDKUTILS_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-sdkutils \
  -B aws-c-sdkutils/build \
  && cmake --build aws-c-sdkutils/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_CAL_VERSION}" https://github.com/awslabs/aws-c-cal.git \
  && test "$(git -C aws-c-cal rev-parse HEAD)" = "${AWS_C_CAL_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-cal \
  -B aws-c-cal/build \
  && cmake --build aws-c-cal/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_IO_VERSION}" https://github.com/awslabs/aws-c-io.git \
  && test "$(git -C aws-c-io rev-parse HEAD)" = "${AWS_C_IO_COMMIT}" \
  && cmake \
  -DUSE_VSOCK=1 \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-io \
  -B aws-c-io/build \
  && cmake --build aws-c-io/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_COMPRESSION_VERSION}" https://github.com/awslabs/aws-c-compression.git \
  && test "$(git -C aws-c-compression rev-parse HEAD)" = "${AWS_C_COMPRESSION_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-compression \
  -B aws-c-compression/build \
  && cmake --build aws-c-compression/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_HTTP_VERSION}" https://github.com/awslabs/aws-c-http.git \
  && test "$(git -C aws-c-http rev-parse HEAD)" = "${AWS_C_HTTP_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-http \
  -B aws-c-http/build \
  && cmake --build aws-c-http/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${AWS_C_AUTH_VERSION}" https://github.com/awslabs/aws-c-auth.git \
  && test "$(git -C aws-c-auth rev-parse HEAD)" = "${AWS_C_AUTH_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-c-auth \
  -B aws-c-auth/build \
  && cmake --build aws-c-auth/build --parallel "$(nproc)" --target install

RUN git clone --depth 1 --branch "${JSON_C_VERSION}" https://github.com/json-c/json-c.git \
  && test "$(git -C json-c rev-parse HEAD)" = "${JSON_C_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S json-c \
  -B json-c/build \
  && cmake --build json-c/build --parallel "$(nproc)" --target install

RUN curl --fail --location --silent --show-error --output rustup-init \
  "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-musl/rustup-init" \
  && echo "${RUSTUP_INIT_SHA256}  rustup-init" | sha256sum -c - \
  && chmod +x rustup-init \
  && ./rustup-init -y --profile minimal \
  --default-toolchain "${RUST_TOOLCHAIN_VERSION}" \
  && rm rustup-init

ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone --depth 1 --branch "${AWS_NE_NSM_API_VERSION}" https://github.com/aws/aws-nitro-enclaves-nsm-api.git \
  && test "$(git -C aws-nitro-enclaves-nsm-api rev-parse HEAD)" = "${AWS_NE_NSM_API_COMMIT}" \
  && cd aws-nitro-enclaves-nsm-api \
  && cargo build --release --jobs "$(nproc)" -p nsm-lib \
  && cp target/release/libnsm.so /usr/lib/libnsm.so \
  && cp target/release/nsm.h /usr/include/nsm.h

RUN git clone --depth 1 --branch "${AWS_NE_SDK_C_VERSION}" https://github.com/aws/aws-nitro-enclaves-sdk-c.git \
  && test "$(git -C aws-nitro-enclaves-sdk-c rev-parse HEAD)" = "${AWS_NE_SDK_C_COMMIT}" \
  && cmake \
  -DCMAKE_PREFIX_PATH=/usr \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -GNinja \
  -S aws-nitro-enclaves-sdk-c \
  -B aws-nitro-enclaves-sdk-c/build \
  && cmake --build aws-nitro-enclaves-sdk-c/build --parallel "$(nproc)" --target kmstool_enclave_cli

RUN mkdir -p /out/bin /out/lib \
  && cp aws-nitro-enclaves-sdk-c/build/bin/kmstool-enclave-cli/kmstool_enclave_cli /out/bin/kmstool_enclave_cli \
  && cp /usr/lib/libnsm.so /out/lib/libnsm.so \
  && cp /usr/lib/libgcc_s.so.1 /out/lib/libgcc_s.so.1

RUN chmod +x /out/bin/kmstool_enclave_cli \
  && echo "---- builder file ----" \
  && file /out/bin/kmstool_enclave_cli \
  && echo "---- builder ldd ----" \
  && LD_LIBRARY_PATH=/out/lib ldd /out/bin/kmstool_enclave_cli || true

FROM scratch AS kmstool-artifacts
COPY --from=kmstool-builder /out/ /

FROM node:24-alpine AS kmstool-node-alpine-test

RUN apk add --no-cache \
  ca-certificates \
  file \
  libgcc \
  libstdc++

COPY --from=kmstool-builder /out/bin/kmstool_enclave_cli /usr/local/bin/kmstool_enclave_cli
COPY --from=kmstool-builder /out/lib/ /usr/local/lib/
COPY --from=kmstool-builder /out/kmstool-build-versions.txt /usr/local/share/kmstool-build-versions.txt

ENV LD_LIBRARY_PATH="/usr/local/lib"

RUN set -e; \
  chmod +x /usr/local/bin/kmstool_enclave_cli; \
  echo "---- versions ----"; \
  cat /usr/local/share/kmstool-build-versions.txt; \
  echo "---- file ----"; \
  file /usr/local/bin/kmstool_enclave_cli; \
  echo "---- ldd ----"; \
  ldd /usr/local/bin/kmstool_enclave_cli || true; \
  if ldd /usr/local/bin/kmstool_enclave_cli 2>/dev/null | grep -q "not found"; then \
  echo "ERROR: unresolved shared library dependency"; \
  exit 1; \
  fi

CMD ["/usr/local/bin/kmstool_enclave_cli"]
