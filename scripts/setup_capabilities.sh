#!/usr/bin/env bash
# Setup script for NFTex capabilities
# This script sets CAP_NET_ADMIN capability on the NFTex port binary

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Binary path
BINARY_PATH="${1:-priv/libnf_ex}"

echo "NFTex Capabilities Setup"
echo "========================"
echo ""

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo${NC}"
    echo ""
    echo "Usage:"
    echo "  sudo $0 [binary_path]"
    echo ""
    echo "Example:"
    echo "  sudo $0 priv/libnf_ex"
    exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}Error: Binary not found at: $BINARY_PATH${NC}"
    echo ""
    echo "Have you compiled the project?"
    echo "  mix compile"
    echo ""
    echo "Or specify the correct path:"
    echo "  sudo $0 /path/to/libnf_ex"
    exit 1
fi

# Check if setcap is available
if ! command -v setcap &> /dev/null; then
    echo -e "${RED}Error: setcap command not found${NC}"
    echo ""
    echo "Install libcap2-bin:"
    echo "  sudo apt-get install libcap2-bin   # Debian/Ubuntu"
    echo "  sudo yum install libcap            # RHEL/CentOS"
    exit 1
fi

# Check if filesystem supports capabilities
MOUNT_POINT=$(df "$BINARY_PATH" | tail -1 | awk '{print $6}')
FS_TYPE=$(df -T "$BINARY_PATH" | tail -1 | awk '{print $2}')

echo "Binary path: $BINARY_PATH"
echo "Mount point: $MOUNT_POINT"
echo "Filesystem:  $FS_TYPE"
echo ""

if [[ "$FS_TYPE" == "nfs" ]] || [[ "$FS_TYPE" == "tmpfs" ]]; then
    echo -e "${YELLOW}Warning: Filesystem type '$FS_TYPE' may not support extended attributes${NC}"
    echo "Capabilities might not persist. Consider using a local filesystem."
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Set capabilities
echo "Setting capabilities..."
if setcap cap_net_admin+ep "$BINARY_PATH"; then
    echo -e "${GREEN}✓ Capabilities set successfully${NC}"
else
    echo -e "${RED}✗ Failed to set capabilities${NC}"
    exit 1
fi

# Verify capabilities were set
echo ""
echo "Verifying capabilities..."
if getcap "$BINARY_PATH" | grep -q "cap_net_admin"; then
    CAPS=$(getcap "$BINARY_PATH")
    echo -e "${GREEN}✓ Verification successful${NC}"
    echo "  $CAPS"
else
    echo -e "${RED}✗ Verification failed${NC}"
    echo "Capabilities were not set correctly"
    exit 1
fi

# Show usage instructions
echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "You can now run NFTex as a regular user:"
echo "  iex -S mix"
echo ""
echo "Or in production:"
echo "  MIX_ENV=prod mix release"
echo "  _build/prod/rel/my_app/bin/my_app start"
echo ""
echo -e "${YELLOW}Note: You'll need to re-run this script after each recompilation${NC}"
echo ""

# Optional: Add to git hooks suggestion
if [ -d ".git" ]; then
    echo "💡 Tip: Add this to a post-build script:"
    echo "   mix compile && sudo $0"
fi
