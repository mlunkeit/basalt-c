FROM debian:testing-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    gcc \
    g++ \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
RUN cmake --build build

CMD ["./build/run_tests"]