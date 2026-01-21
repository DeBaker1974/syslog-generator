#!/bin/bash
# switch.sh - Quick target switcher

ENV_FILE=".env"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_usage() {
    echo "Usage: ./switch.sh [target]"
    echo ""
    echo "Targets:"
    grep -E "^ES_[A-Z]+_URL=" "$ENV_FILE" 2>/dev/null | sed 's/ES_\([A-Z]*\)_URL=.*/  \1/' | tr '[:upper:]' '[:lower:]' | sort -u
    echo ""
    echo "Current: $(grep '^ES_TARGET=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo 'none')"
}

get_current() {
    grep '^ES_TARGET=' "$ENV_FILE" 2>/dev/null | cut -d= -f2
}

list_targets() {
    echo -e "${CYAN}Available Elasticsearch Targets:${NC}"
    echo ""

    current=$(get_current)

    # Find all targets
    targets=$(grep -E "^ES_[A-Z]+_URL=" "$ENV_FILE" 2>/dev/null | sed 's/ES_\([A-Z]*\)_URL=.*/\1/' | sort -u)

    for target in $targets; do
        target_lower=$(echo "$target" | tr '[:upper:]' '[:lower:]')
        url=$(grep "^ES_${target}_URL=" "$ENV_FILE" | cut -d= -f2)

        if [ "$target_lower" = "$current" ]; then
            echo -e "  ${GREEN}▶ ${target_lower}${NC} (active)"
        else
            echo -e "    ${target_lower}"
        fi
        echo -e "      URL: $url"
    done
    echo ""
}

switch_target() {
    target=$(echo "$1" | tr '[:lower:]' '[:upper:]')
    target_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')

    # Check if target exists
    if ! grep -q "^ES_${target}_URL=" "$ENV_FILE" 2>/dev/null; then
        echo -e "${RED}Error: Target '$target_lower' not found${NC}"
        echo ""
        show_usage
        exit 1
    fi

    # Update ES_TARGET
    if grep -q "^ES_TARGET=" "$ENV_FILE"; then
        # Replace existing
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^ES_TARGET=.*/ES_TARGET=$target_lower/" "$ENV_FILE"
        else
            sed -i "s/^ES_TARGET=.*/ES_TARGET=$target_lower/" "$ENV_FILE"
        fi
    else
        # Add new
        echo "ES_TARGET=$target_lower" >> "$ENV_FILE"
    fi

    url=$(grep "^ES_${target}_URL=" "$ENV_FILE" | cut -d= -f2)
    echo -e "${GREEN}✓ Switched to: ${target_lower}${NC}"
    echo -e "  URL: $url"
}

test_target() {
    target=$1
    if [ -z "$target" ]; then
        target=$(get_current)
    fi

    if [ -z "$target" ]; then
        echo -e "${RED}No target specified or active${NC}"
        exit 1
    fi

    echo -e "${CYAN}Testing connection to $target...${NC}"
    python -c "
from syslog_generator.config import load_config
from syslog_generator.main import init_elasticsearch

config = load_config()
if init_elasticsearch(config):
    print('Connection successful!')
else:
    print('Connection failed!')
    exit(1)
"
}

# Main
case "${1:-}" in
    ""|"-h"|"--help")
        show_usage
        ;;
    "-l"|"--list"|"list")
        list_targets
        ;;
    "-t"|"--test")
        test_target "$2"
        ;;
    "-c"|"--current")
        get_current
        ;;
    *)
        switch_target "$1"
        ;;
esac
