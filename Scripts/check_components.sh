#!/bin/bash

SESSION="check_components"

# Start new tmux session
tmux new-session -d -s $SESSION

# First pane
tmux send-keys -t $SESSION "docker exec -it aster1 bash -c 'ps aux; bash'" C-m

# Remaining panes
for i in {2..20}; do
    tmux split-window -t $SESSION
    tmux select-layout -t $SESSION tiled
    tmux send-keys -t $SESSION "docker exec -it aster$i bash -c 'ps aux; bash'" C-m
done

# Attach to session
tmux attach-session -t $SESSION
