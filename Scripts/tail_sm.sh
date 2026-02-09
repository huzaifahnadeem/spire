#!/bin/bash

SESSION="tail_sm"

# Start new tmux session
tmux new-session -d -s $SESSION

# First pane
tmux send-keys -t $SESSION "docker exec -it goldenrod1 bash -c 'tail -f prime/bin/logs/sm.log; bash'" C-m

# Remaining panes
for i in {2..8}; do
    tmux split-window -t $SESSION
    tmux select-layout -t $SESSION tiled
    tmux send-keys -t $SESSION "docker exec -it goldenrod$i bash -c 'tail -f prime/bin/logs/sm.log; bash'" C-m
done

# Attach to session
tmux attach-session -t $SESSION
