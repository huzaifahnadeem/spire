#!/bin/bash

# List of process names to kill
PROCESSES=(
  config_agent
  spines
  scada_master
  prime
  jhu_hmi
  ems_hmi
  pnnl_hmi
)

echo "Killing Spire-related processes..."

for proc in "${PROCESSES[@]}"; do
  pkill -9 "$proc" && echo "Killed $proc" || echo "$proc not running"
done

# Kill all tmux sessions
tmux kill-server && echo "Killed tmux server" || echo "tmux server not running"

rm -f /tmp/spines8200
rm -f /tmp/spines8200data

echo "Done."
