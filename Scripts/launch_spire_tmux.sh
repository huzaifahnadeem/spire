#!/bin/bash

session="config_agent_$(date +%Y%m%d_%H%M%S)"
containers=(spire1 spire2 spire3 spire4 spire5 spire6)
hosts=(goldenrod1 goldenrod2 goldenrod3 goldenrod4 goldenrod11 goldenrod10)

# Start the first container with config_agent
tmux new-session -d -s "$session" -n "config_agent" \
    "docker exec -it ${containers[0]} bash -c 'cd prime/bin && ./config_agent -h ${hosts[0]}; exec bash'"

# Start containers 2 to 6
for i in {1..5}; do
  tmux split-window -t "$session:0" -v
  tmux select-layout -t "$session:0" tiled
  tmux send-keys -t "$session:0.$i" \
    "docker exec -it ${containers[$i]} bash -c 'cd prime/bin && ./config_agent -h ${hosts[$i]}; exec bash'" C-m
done

# Final pane: just bash on spire1
tmux split-window -t "$session:0" -v
tmux select-layout -t "$session:0" tiled
tmux send-keys -t "$session:0.6" \
  "docker exec -it spire1 bash" C-m

# Attach to the tmux session
tmux select-layout -t "$session:0" tiled
tmux attach -t "$session"
