#!/bin/sh
set -e

# Download zig cross-compiler
echo "[1/4] Downloading zig cross-compiler..."
apt-get update -qq && apt-get install -y -qq xz-utils wget 2>/dev/null
wget -q https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz -O /tmp/zig.tar.xz
tar -xJf /tmp/zig.tar.xz -C /tmp/
ZIG=/tmp/zig-linux-x86_64-0.13.0/zig
chmod +x "$ZIG"
echo "zig ok: $($ZIG version)"

# Create wrapper scripts
echo "[2/4] Setting up zig CC/CXX wrappers..."
cat > /tmp/zigcc << 'EOF'
#!/bin/sh
exec /tmp/zig-linux-x86_64-0.13.0/zig cc -target x86_64-windows-gnu "$@"
EOF
cat > /tmp/zigcxx << 'EOF'
#!/bin/sh
exec /tmp/zig-linux-x86_64-0.13.0/zig c++ -target x86_64-windows-gnu "$@"
EOF
chmod +x /tmp/zigcc /tmp/zigcxx

echo "[3/4] Building forensiq.exe..."
cd /src
GOOS=windows GOARCH=amd64 CC=/tmp/zigcc CXX=/tmp/zigcxx CGO_ENABLED=1 \
  go build -o forensiq.exe .

echo "[4/4] BUILD_OK: $(ls -lh forensiq.exe)"
