FROM emscripten/emsdk:latest AS wasm-build

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    autoconf \
    automake \
    libtool

RUN wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz \
 && tar -xzf libsodium-1.0.19.tar.gz \
 && cd libsodium-stable \
 && emconfigure ./configure \
      --disable-shared \
      --enable-static \
      --prefix=/opt/sodium-wasm \
 && emmake make -j$(nproc) \
 && emmake make install

WORKDIR /client

COPY NKClient/ .
COPY NKProtocol/ ../NKProtocol/
RUN emcmake cmake -S . -B build
RUN cmake --build build

FROM golang:1.24-alpine AS go-build

RUN apk add --no-cache \
    build-base \
    cmake \
    git \
    pkgconfig \
    zlib-dev \
    libsodium-dev

ENV CGO_ENABLED=1

WORKDIR /app

COPY NKProtocol/ ./NKProtocol/

WORKDIR /app/NKProtocol
RUN cmake -S . -B build
RUN cmake --build build

WORKDIR /app

COPY NKServer/ ./NKServer/

WORKDIR /app/NKServer

RUN go mod download
RUN go build -o NKServer

FROM alpine:latest

RUN apk add --no-cache libsodium

WORKDIR /app

COPY --from=go-build /app/NKServer/NKServer .
COPY --from=wasm-build /client/build/ ./client/

EXPOSE 8080

CMD ["./NKServer"]
