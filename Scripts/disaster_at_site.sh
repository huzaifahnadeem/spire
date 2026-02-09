#!/bin/bash

# Simulate a site being taken offline by stopping its containers 

if [ -z "$1" ]; then
    echo "Usage: $0 <1|2>"
    echo "  1 = Simulate failure at Site 1"
    echo "  2 = Simulate failure at Site 2"
    exit 1
fi

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

echo "Simulating failure at $site by stopping containers"

for container in "${containers[@]}"; do
    {
        echo "Stopping container: $container"
        docker stop "$container" >/dev/null 2>&1 || echo "  Warning: $container not running"
    } &
done

# Wait for all background jobs to finish
wait

echo "$site has been taken offline."
