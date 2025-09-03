#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "[*] Identifying operating system..."

# Detect OS and Package Manager
OS=""
PM=""
if [ -f /etc/debian_version ]; then
  OS="debian"
  PM="apt-get"
elif [ -f /etc/redhat-release ]; then
  OS="redhat"
  PM="dnf"
elif [ "$(uname -s)" = "Darwin" ]; then
  OS="darwin"
  PM="brew"
else
  echo "[!] Unsupported operating system."
  exit 1
fi

echo "[*] System identified as: $OS"

# --- Install Base Dependencies ---
echo "[*] Installing base dependencies (git, curl, python, perl, etc.)..."
if [ "$OS" = "debian" ]; then
  sudo $PM update
  sudo $PM install -y python3 python3-pip git curl wget build-essential perl
elif [ "$OS" = "redhat" ]; then
  sudo $PM install -y python3 python3-pip git curl wget gcc-c++ perl perl-Net-SSLeay
elif [ "$OS" = "darwin" ]; then
  if ! command -v brew &> /dev/null; then
    echo "[*] Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
  brew install python git curl wget go
fi

# --- Install Go and Go-based Tools ---
echo "[*] Setting up Go environment..."
if [ -n "$ZSH_VERSION" ]; then
  PROFILE_FILE=~/.zshrc
else
  PROFILE_FILE=~/.bashrc
fi
if [ "$OS" = "darwin" ]; then
    PROFILE_FILE=~/.zprofile
fi

if ! command -v go &> /dev/null; then
    echo "[*] Go not found. Installing Go..."
    GO_VERSION="1.22.5"
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then GO_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then GO_ARCH="arm64"; fi
    GO_FILE="go${GO_VERSION}.$(uname -s | tr '[:upper:]' '[:lower:]')-${GO_ARCH}.tar.gz"

    wget "https://go.dev/dl/${GO_FILE}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${GO_FILE}"
    rm "${GO_FILE}"
fi

echo "[*] Configuring Go PATH in ${PROFILE_FILE}..."
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

if ! grep -q "GOPATH" "$PROFILE_FILE"; then
  {
    echo ''
    echo '# Go environment configuration'
    echo 'export GOPATH=$HOME/go'
    echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin'
  } >> "$PROFILE_FILE"
fi

echo "[*] Installing Go-based security tools..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/OJ/gobuster/v3@latest

# --- Install Other Tools ---
echo "[*] Creating tools directory at ~/tools..."
mkdir -p ~/tools

# Install sqlmap
if [ ! -d ~/tools/sqlmap ]; then
  echo "[*] Installing sqlmap..."
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap
else
  echo "[*] sqlmap already installed. Skipping."
fi

# Install XSStrike
if [ ! -d ~/tools/XSStrike ]; then
  echo "[*] Installing XSStrike..."
  git clone https://github.com/s0md3v/XSStrike.git ~/tools/XSStrike
  echo "[*] Installing XSStrike dependencies..."
  pip3 install -r ~/tools/XSStrike/requirements.txt
else
  echo "[*] XSStrike already installed. Skipping."
fi

# Install Nikto
if [ ! -d ~/tools/nikto ]; then
    echo "[*] Nikto not found, cloning from official repository..."
    git clone https://github.com/sullo/nikto.git ~/tools/nikto
else
    echo "[*] Nikto directory already exists. Skipping clone."
fi

# Add tools to PATH
if ! grep -q "AUWASP_TOOLS_PATH" "$PROFILE_FILE"; then
  {
    echo ''
    echo '# AuWASP Tools PATH'
    echo 'export PATH=$PATH:$HOME/tools/sqlmap:$HOME/tools/XSStrike:$HOME/tools/nikto/program'
  } >> "$PROFILE_FILE"
fi

# --- Final Message ---
echo ""
echo "✅ Setup Complete!"
echo "--------------------------------------------------"
echo "IMPORTANT: To use the installed tools,"
echo "you must reload your shell configuration by running:"
echo ""
echo "  source ${PROFILE_FILE}"
echo ""
echo "Or simply open a new terminal window."
echo "--------------------------------------------------"