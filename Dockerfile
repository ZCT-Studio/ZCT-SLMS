# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive VCPKG_ROOT=/opt/vcpkg VCPKG_FORCE_SYSTEM_BINARIES=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git curl ca-certificates zip unzip tar \
    pkg-config autoconf automake libtool linux-libc-dev && rm -rf /var/lib/apt/lists/*
ARG ZCT_SLMS_BUILD_VCPKG_REF=2025.06.13
RUN git clone --depth 1 --branch "${ZCT_SLMS_BUILD_VCPKG_REF}" https://github.com/microsoft/vcpkg.git /opt/vcpkg \
    && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics
RUN apt-get update && apt-get install -y --no-install-recommends bison flex \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG ZCT_SLMS_BUILD_DATABASE_FEATURES=postgres;mysql
ARG ZCT_SLMS_BUILD_JOBS=2
COPY vcpkg.json CMakeLists.txt ./
COPY cmake/ cmake/
COPY src/ src/
COPY libs/ libs/
RUN --mount=type=cache,target=/root/.cache/vcpkg \
    --mount=type=cache,target=/opt/vcpkg/downloads \
    export VCPKG_MAX_CONCURRENCY="${ZCT_SLMS_BUILD_JOBS}" \
    && cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
    "-DVCPKG_MANIFEST_FEATURES=${ZCT_SLMS_BUILD_DATABASE_FEATURES}" \
    && cmake --build /build --parallel "${ZCT_SLMS_BUILD_JOBS}" \
    && strip /build/ZCT-SLMS \
    && mkdir -p /runtime-libs \
    && ldd /build/ZCT-SLMS > /tmp/runtime-deps \
    && ! grep -q 'not found' /tmp/runtime-deps \
    && awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' /tmp/runtime-deps \
       | sort -u | xargs -r -I '{}' cp --parents '{}' /runtime-libs/

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 zct_slms \
    && useradd --uid 10001 --gid zct_slms --no-create-home --shell /usr/sbin/nologin zct_slms
COPY --from=build /runtime-libs/lib/ /usr/lib/
COPY --from=build /build/ZCT-SLMS /usr/local/bin/ZCT-SLMS
WORKDIR /app
COPY migrations/ migrations/
COPY docker/config.yaml config/config.yaml
COPY LICENSE LICENSE
RUN mkdir -p data logs zct_slms_web uploads tmp && chown -R 10001:10001 /app
USER 10001:10001
EXPOSE 17112
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail --silent --max-time 4 http://127.0.0.1:17112/api/v1/ping || exit 1
ENTRYPOINT ["/usr/local/bin/ZCT-SLMS"]
CMD ["/app/config/config.yaml"]
