@echo off
setlocal

set "GOBIN=%USERPROFILE%\go\bin"
set "SRC=%~dp0"
set "SRC=%SRC:~0,-1%"

echo [1/2] Building forensiq.exe via Docker (cross-compile Linux->Windows)...
docker run --rm ^
  -v "%SRC%:/src" ^
  -w /src ^
  golang:1.23 ^
  sh -c "apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 && GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 go build -o forensiq.exe ."

if errorlevel 1 (
    echo ERROR: Docker build failed.
    exit /b 1
)

echo [2/2] Copying to %GOBIN%...
if not exist "%GOBIN%" mkdir "%GOBIN%"
copy /Y "%SRC%\forensiq.exe" "%GOBIN%\forensiq.exe"

echo Done: forensiq.exe installed to %GOBIN%
echo You can now run: forensiq --help
