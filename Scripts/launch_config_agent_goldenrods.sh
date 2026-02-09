#!/bin/bash

SESSION="goldenrod_config_agents"

# Start new tmux session
tmux new-session -d -s $SESSION

# First pane
tmux send-keys -t $SESSION "docker exec -it goldenrod1 bash -c 'cd /app/spire/prime/bin && ./config_agent -h goldenrod1 -l 1'" C-m

# Remaining panes
for i in {2..6}; do
    tmux split-window -t $SESSION
    tmux select-layout -t $SESSION tiled
    tmux send-keys -t $SESSION "docker exec -it goldenrod$i bash -c 'cd /app/spire/prime/bin && ./config_agent -h goldenrod$i -l 1'" C-m
done

# Attach to session
tmux attach-session -t $SESSION
