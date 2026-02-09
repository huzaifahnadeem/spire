#!/bin/bash


NUM_HOSTS=6
SESSION="goldenrods_tail_sm"

# Start new tmux session
tmux new-session -d -s $SESSION

# First pane (goldenrod1)
tmux send-keys -t $SESSION "docker exec -it goldenrod1 bash -c 'tail -F prime/bin/logs/sm.log 2>/dev/null'" C-m

# Remaining panes (goldenrod2 to goldenrodN)
for ((i=2; i<=NUM_HOSTS; i++)); do
    tmux split-window -t $SESSION
    tmux select-layout -t $SESSION tiled
    tmux send-keys -t $SESSION "docker exec -it goldenrod$i bash -c 'tail -F prime/bin/logs/sm.log 2>/dev/null'" C-m
done

# Attach to session
tmux attach-session -t $SESSION
