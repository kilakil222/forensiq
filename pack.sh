#!/bin/bash
set -e
apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 zip > /dev/null 2>&1
cd /build

# Build fresh
rm -f forensiq.exe
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc-posix \
  CXX=x86_64-w64-mingw32-g++-posix \
  go build -mod=vendor -ldflags='-s -w -extldflags -lpthread' -o forensiq.exe . 2>&1 | grep -v 'warning:'
echo "Build exit: $?"
ls -lh forensiq.exe

# Bundle DLLs
GCC_DIR=/usr/lib/gcc/x86_64-w64-mingw32/12-posix
PTHREAD_DLL=/usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll
cp "$GCC_DIR/libstdc++-6.dll" .
cp "$GCC_DIR/libgcc_s_seh-1.dll" .
cp "$PTHREAD_DLL" .
rm -f forensiq.zip
zip forensiq.zip forensiq.exe libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll
ls -lh forensiq.zip
sha256sum forensiq.zip
rm -f libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll
