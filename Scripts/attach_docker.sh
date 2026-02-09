#!/bin/bash

SESSION="aster_exec"

# Start a new tmux session with the first pane
tmux new-session -d -s $SESSION -n "asters" "docker exec -it aster1 bash -c \"ps aux | grep -E 'spines|prime|scada'; bash\""

# Split horizontally for goldenrod2–goldenrod6
for i in {2..20}; do
    tmux split-window -t "$SESSION:0" -h "docker exec -it aster$i bash -c \"ps aux | grep -E 'spines|prime|scada'; bash\""
    tmux select-layout -t $SESSION:0 tiled
done

# Focus on the first pane
tmux select-pane -t $SESSION:0.0

# Attach to the session
tmux attach -t $SESSION
