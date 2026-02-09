#!/bin/bash

NUM_HOSTS=18
SESSION="asters_tail_prime"

# Start new tmux session
tmux new-session -d -s $SESSION

# First pane (aster1)
tmux send-keys -t $SESSION "docker exec -it aster1 bash -c 'tail -F prime/bin/logs/prime.log 2>/dev/null'" C-m

# Remaining panes (aster2 to asterN)
for ((i=2; i<=NUM_HOSTS; i++)); do
    tmux split-window -t $SESSION
    tmux select-layout -t $SESSION tiled
    tmux send-keys -t $SESSION "docker exec -it aster$i bash -c 'tail -F prime/bin/logs/prime.log 2>/dev/null'" C-m
done

# Attach to session
tmux attach-session -t $SESSION
