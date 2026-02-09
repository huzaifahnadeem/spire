#!/bin/bash

session="spines_ext_$(date +%Y%m%d_%H%M%S)"
containers=(goldenrod1 goldenrod2 goldenrod3 goldenrod4 goldenrod5 goldenrod6 goldenrod7 goldenrod8)
ips=(192.168.0.101 192.168.0.102 192.168.0.103 192.168.0.104 192.168.0.105 192.168.0.106 192.168.0.107 192.168.0.108)

tmux new-session -d -s "$session" -n "spines_ext" \
    "docker exec -it ${containers[0]} bash -c 'cd spines/daemon && ./spines -c spines_ext.conf -p 8120 -I ${ips[0]}; exec bash'"

for i in {1..7}; do
  tmux split-window -t "$session:0" -v
  tmux select-layout -t "$session:0" tiled
  tmux send-keys -t "$session:0.$i" \
    "docker exec -it ${containers[$i]} bash -c 'cd spines/daemon && ./spines -c spines_ext.conf -p 8120 -I ${ips[$i]}; exec bash'" C-m
done

tmux select-layout -t "$session:0" tiled
tmux attach -t "$session"
