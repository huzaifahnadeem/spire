#!/bin/bash

DEST_DIR="./collected_logs"
mkdir -p "$DEST_DIR"

for i in {1..18}; do
    container="aster$i"

    echo "Copying logs from $container..."

    docker cp "$container:/app/spire/prime/bin/logs/prime.log" "$DEST_DIR/prime_$i.log" 2>/dev/null \
        && echo "  prime$i.log copied." || echo "  Warning: prime.log not found in $container."

    docker cp "$container:/app/spire/prime/bin/logs/sm.log" "$DEST_DIR/sm_$i.log" 2>/dev/null \
        && echo "  sm$i.log copied." || echo "  Warning: sm.log not found in $container."
done

echo "Log collection complete. Files are in '$DEST_DIR/'"
