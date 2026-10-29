#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${TOOLS_DIR:-$HOME/ReverseEngineering/Tools}"
VENV="${VENV:-$HERE/.venv}"
JADX_VER="1.5.3"
APKTOOL_VER="2.9.3"

say(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

install_system() {
  say "system packages"
  if command -v apt-get >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y python3.11 python3.11-venv python3.11-dev \
        build-essential pkg-config git wget unzip p7zip-full \
        openjdk-21-jdk-headless libffi-dev
  elif command -v dnf >/dev/null; then
    sudo dnf install -y python3.11 python3.11-devel gcc gcc-c++ make git wget \
        unzip p7zip java-21-openjdk-headless libffi-devel
  elif command -v pacman >/dev/null; then
    sudo pacman -Sy --needed --noconfirm python git wget unzip p7zip \
        jdk-openjdk base-devel libffi
  else
    echo "Unknown distro - install manually: python3.11, venv, build tools, \
openjdk-21, git wget unzip p7zip, libffi" >&2
  fi
}

install_python() {
  say "python venv + pinned RE stack"
  local PY
  PY="$(command -v python3.11 || command -v python3)"
  "$PY" -m venv "$VENV"
  . "$VENV/bin/activate"
  python -m pip install --upgrade pip wheel
  if ! python -m pip install -r "$HERE/requirements.txt"; then
    echo "retrying lief from nightly index..."
    python -m pip install --index-url https://lief.re/packages/ "lief==1.0.0.dev0" || true
    python -m pip install -r "$HERE/requirements.txt" || true
  fi
}

install_jadx() {
  say "jadx $JADX_VER"
  mkdir -p "$TOOLS_DIR"
  if [ ! -x "$TOOLS_DIR/jadx/bin/jadx" ]; then
    wget -q -O /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip"
    rm -rf "$TOOLS_DIR/jadx" && mkdir -p "$TOOLS_DIR/jadx"
    unzip -q /tmp/jadx.zip -d "$TOOLS_DIR/jadx"
    chmod +x "$TOOLS_DIR/jadx/bin/jadx"
  fi
}

install_apktool() {
  say "apktool $APKTOOL_VER"
  if [ ! -f "$TOOLS_DIR/apktool.jar" ]; then
    wget -q -O "$TOOLS_DIR/apktool.jar" \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VER}/apktool_${APKTOOL_VER}.jar"
  fi
}

verify() {
  say "verify"
  . "$VENV/bin/activate"
  python "$HERE/verify_env.py" || true
  echo
  echo "jadx:   $("$TOOLS_DIR/jadx/bin/jadx" --version 2>/dev/null || echo MISSING)"
  echo "java:   $(java -version 2>&1 | head -1)"
  echo
  echo "Activate later with:  . $VENV/bin/activate"
  echo "jadx on PATH:         export PATH=\"$TOOLS_DIR/jadx/bin:\$PATH\""
}

install_system
install_python
install_jadx
install_apktool
verify
say "done"
