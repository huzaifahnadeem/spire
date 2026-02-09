#!/bin/bash

SESSION="disseminate"
containers=(aster1 aster7 aster13 aster19 aster20 goldenrod1)
cmd="cd prime/bin; bash"

# Start a new tmux session with the first container
tmux new-session -d -s $SESSION "docker exec -it ${containers[0]} bash -c '$cmd'"

# Create a new pane for each remaining container
for ((i=1; i<${#containers[@]}; i++)); do
    tmux split-window -t $SESSION -v "docker exec -it ${containers[$i]} bash -c '$cmd'"
    tmux select-layout -t $SESSION tiled
done

# Attach to the session
tmux attach-session -t $SESSION
