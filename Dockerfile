FROM golang:1.24-bookworm
RUN apt-get update && apt-get install -y gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 zip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
ENV GOOS=windows
ENV GOARCH=amd64
ENV CGO_ENABLED=1
ENV CC=x86_64-w64-mingw32-gcc-posix
ENV CXX=x86_64-w64-mingw32-g++-posix
RUN go build -mod=vendor -ldflags="-s -w -extldflags '-lpthread'" -o forensiq.exe . && \
    cp /usr/lib/gcc/x86_64-w64-mingw32/12-posix/libstdc++-6.dll . && \
    cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll .
