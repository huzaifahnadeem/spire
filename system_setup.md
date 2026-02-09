# **Project Setup & Configuration Documentation**

## **1. Spines Setup**

### **Key Generation**

* Run the `gen_keys` script or tool to generate keys for all hosts in your Spines control network.
* Ensure the number of keys generated matches the number of participating hosts.

### **Topology Configuration**

* Create a `spines_ctrl.conf` file for each site.

  * This file should:

    * Include all site hosts.
    * Define a full mesh topology among them.



## **2. Configuration Manager Setup**

### **Config Manager Key Generation**

* Run the `gen_conf_manager_keys.sh` script:

  * This creates the public/private keypair for the Configuration Manager.
  * Keys are stored in `cm_keys/`.



## **3. Configuration Preparation and Dissemination**

### **Step 1: Generate TPM Keys**

```sh
./gen_tpm_keys <unprocessed_config.yaml>
```

* Generates TPM keypairs for all hosts.
* Outputs private keys to `tpm_keys/<hostname>_tpm_private.pem`.
* Outputs public keys into the yaml structure.

> **Note:**
>
> * Each host must have:
>
>   * Its own private key.
>   * Every other host's public key.



### **Step 2: Process the Configuration**

```sh
./config_manager -i <input_yaml_path> [-o <output_path>]
```

* This:

  * Encrypts and signs all necessary key material.
  * Writes the finalized configuration to:

    * `post_configs/<input_yaml_filename>` by default.
* This output is now in ready-to-disseminate form.



### **Step 3: Prepare Hosts for Reconfiguration**

For each host to be reconfigured:

* Ensure `spines_ctrl` is running.
* Copy the Configuration Manager’s public key to the host's `cm_keys/` directory.
* Launch the configuration agent:

```sh
./config_agent -h <host_name> [-a spines_addr] [-p spines_port] [-l log_mode]
```

**Options:**

* `-h <host_name>` — must match `host->name` in the YAML config.
* `-a <spines_addr>` — default: `127.0.0.1`.
* `-p <spines_port>` — default: `8200`.
* `-l <log_mode>` — 0 = console (default), 1 = file.



### **Step 4: Disseminate the Configuration**

Once all agents are running and the Configuration Manager is ready:

Run the disseminator from any host in a site:

```sh
./config_disseminator [-i config_id] [-c config_file] [-a spines_addr] [-p spines_port]
```

**Options:**

* `-i config_id` — Global config ID (must match the config file). Default: 1.
* `-c config_file` — Path to the post-processed config.
* `-a spines_addr` — Default: IPC on localhost.
* `-p spines_port` — Default: `8200`.



### **After Dissemination**

* The configuration is multicast to all hosts.
* Each `config_agent` will receive the configuration, verify the signature, and:

  * Start or kill components according to the configuration.


