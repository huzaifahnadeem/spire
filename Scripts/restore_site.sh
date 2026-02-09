#!/bin/bash

# Restores a site by restarting the associated Docker containers

if [ -z "$1" ]; then
    echo "Usage: $0 <1|2>"
    echo "  1 = Restart containers for Site 1 (aster1 to aster6)"
    echo "  2 = Restart containers for Site 2 (aster7 to aster12)"
    exit 1
fi

# Select containers based on the site
if [ "$1" == "1" ]; then
    site="Site 1"
    containers=(aster1 aster2 aster3 aster4 aster5 aster6)
elif [ "$1" == "2" ]; then
    site="Site 2"
    containers=(aster7 aster8 aster9 aster10 aster11 aster12)
else
    echo "Invalid site number. Use 1 or 2."
    exit 1
fi

echo "Restoring $site by starting containers..."

for container in "${containers[@]}"; do
    echo "Starting container: $container"
    docker start "$container" >/dev/null 2>&1 || echo "  Warning: $container could not be started"
    docker exec "$container" rm -rf /tmp/spines8100 /tmp/spines8120 /tmp/spines8100data /tmp/spines8120data
    docker exec "$container" python3 start_spines.py > /dev/null \
        || echo "  Warning: Failed to start Spines in $container"
done

echo "$site has been brought back online."
