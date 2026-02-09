# **Utility Scripts**

## **1. copy\_logs.sh**

Copies logs from Docker containers (`aster1` to `aster18`) into the `collected_logs/` directory.

* Collect `prime.log` and `sm.log` from each container.
* Rename logs to `prime<id>.log` and `sm<id>.log` for clarity.

## **2. disaster\_at\_site.sh**

Simulates failure of an entire site by stopping its containers.

**Usage:**

```bash
./disaster_at_site.sh <site_id>
```

**Arguments:**

* `1` — Simulate failure of **Site 1** (`aster1–6`)
* `2` — Simulate failure of **Site 2** (`aster7–12`)

* Stops all containers belonging to the selected site.

## **3. launch\_config\_agent\_\*.sh**

Starts `config_agent` processes on designated containers.

Scripts:

* `launch_config_agent_asters.sh` – Launch agents on aster1–18
* `launch_config_agent_goldenrods.sh` – Launch agents on goldenrod hosts

Each script:

* Starts one `config_agent` per container/host
* Automatically detects the container's host name for correct configuration

## **4. launch\_config\_disseminator.sh**

Starts a `tmux` session that opens a terminal pane for the first host in each site, where the `config_disseminator` can be manually run.

* Prepares designated hosts for running the `config_disseminator`.

**Usage:**

```bash
./launch_config_disseminator.sh
```

* Launches a new `tmux` session.
* Creates a separate pane for each selected host.
* Changes directory into the appropriate location (`prime/bin`) within each container or remote host.
* Leaves the terminal open so the user can run the `config_disseminator` interactively.

## **5. tail\_\*.sh**

Uses `docker exec` to attach to tail logs of components (`prime` or `scada_master`) across all containers for live monitoring.

Scripts:

* `tail_prime_asters.sh` – Live tail of `prime.log` on aster1–18
* `tail_prime_goldenrods.sh` – Same, but on goldenrod hosts
* `tail_sm_asters.sh` – Live tail of `sm.log` on aster1–18
* `tail_sm_goldenrods.sh` – Same, but on goldenrod hosts

