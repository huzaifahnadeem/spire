#!/bin/bash

# Usage: ./setup.sh <setup_dir>
# Example: ./setup.sh Scripts/aster/setup1

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <setup_dir>"
    exit 1
fi

SETUP_DIR="$1"
DEST_DIR="$(pwd)"

COMPOSE_FILE="$SETUP_DIR/docker-compose.yml"
SPINES_CONF="$SETUP_DIR/spines_ctrl.conf"
SPINES_DEST="$DEST_DIR/spines/daemon"
LATEST_CONF="$SETUP_DIR/latest.yaml"
LATEST_DEST="$DEST_DIR/prime/bin/received_configs"
DEF_FILE="$SETUP_DIR/def.h"
DEF_DEST="$DEST_DIR/common"

# Validate files exist
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Error: $COMPOSE_FILE not found"
    exit 1
fi

if [ ! -f "$SPINES_CONF" ]; then
    echo "Error: $SPINES_CONF not found"
    exit 1
fi

# Copy files
echo "Copying docker-compose.yml to $DEST_DIR"
cp "$COMPOSE_FILE" "$DEST_DIR/docker-compose.yml"

echo "Copying spines_ctrl.conf to $SPINES_DEST"
mkdir -p "$SPINES_DEST"
cp "$SPINES_CONF" "$SPINES_DEST/spines_ctrl.conf"

# echo "Copying latest.yaml to $LATEST_DEST"
# cp "$LATEST_CONF" "$LATEST_DEST/latest.yaml"

cp "$DEF_FILE" "$DEF_DEST/def.h"

echo "Setup complete."