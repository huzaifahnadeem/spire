/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design
 *   Daniel Qian          Contributions to Trip Master and IDS
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 *
 */

/* Openssl RSA signing and verifying functionality. The openssl_rsa.h header
 * file lists the public functions that can be used to sign messages and verify
 * that signatures are valid. */

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include "openssl_rsa.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "scada_packets.h"

/* Defined Types */
// "ripemd160"
#define RSA_TYPE_PUBLIC 1
#define RSA_TYPE_PRIVATE 2
#define RSA_TYPE_CLIENT_PUBLIC 3
#define RSA_TYPE_CLIENT_PRIVATE 4
#define RSA_TYPE_CONFIG_MNGR_PUBLIC 5
#define RSA_TYPE_CONFIG_MNGR_PRIVATE 6
#define DIGEST_ALGORITHM "sha1"
// #define NUMBER_OF_SERVERS NUM_SM
#define NUMBER_OF_CLIENTS (MAX_EMU_RTU + 50)

/* This flag is used to remove crypto for testing -- this feature eliminates
 * security and Byzantine fault tolerance. */
#define REMOVE_CRYPTO 0

/* Global variables */
RSA *private_rsa; /* My Private Key */
RSA *public_config_mngr_rsa;
RSA *public_rsa_by_server[MAX_NUM_SERVER_SLOTS];
RSA *public_rsa_by_client[NUMBER_OF_CLIENTS + 1];
const EVP_MD *message_digest;
_Thread_local EVP_MD_CTX *mdctx = NULL;
void *pt;
int32 verify_count;

void Gen_Key_Callback(int32 stage, int32 n, void *unused)
{
	UNUSED(stage);
	UNUSED(n);
	UNUSED(unused);
}

void Write_BN(FILE *f, const BIGNUM *bn)
{
	char *bn_buf;

	bn_buf = BN_bn2hex(bn);

	fprintf(f, "%s\n", bn_buf);

	/* Note: The memory for the BIGNUM should be freed if the bignum will not
	 * be used again. TODO */
}

void Write_RSA(int32u rsa_type, int32u server_number, RSA *rsa, const char *keys_dir)
{
	FILE *f;
	char fileName[100];
	const BIGNUM *n, *e, *d;
	const BIGNUM *p, *q;
	const BIGNUM *dmp1, *dmq1, *iqmp;

	/* Write an RSA structure to a file */
	if (rsa_type == RSA_TYPE_PUBLIC)
		snprintf(fileName, 100, "%s/public_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_PRIVATE)
		snprintf(fileName, 100, "%s/private_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CLIENT_PUBLIC)
		snprintf(fileName, 100, "%s/public_client_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CLIENT_PRIVATE)
		snprintf(fileName, 100, "%s/private_client_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CONFIG_MNGR_PUBLIC)
		snprintf(fileName, 100, "%s/public_config_mngr.key", keys_dir);
	else if (rsa_type == RSA_TYPE_CONFIG_MNGR_PRIVATE)
		snprintf(fileName, 100, "%s/private_config_mngr.key", keys_dir);

	f = fopen(fileName, "w");

	RSA_get0_key(rsa, &n, &e, &d);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	Write_BN(f, n);
	Write_BN(f, e);

	if (rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE || rsa_type == RSA_TYPE_CONFIG_MNGR_PRIVATE)
	{
		Write_BN(f, d);
		Write_BN(f, p);
		Write_BN(f, q);
		Write_BN(f, dmp1);
		Write_BN(f, dmq1);
		Write_BN(f, iqmp);
	}
	fprintf(f, "\n");
	fclose(f);
}

void Read_BN(FILE *f, BIGNUM **bn)
{
	char bn_buf[1000];
	char *ret;

	(*bn) = BN_new();
	ret = fgets(bn_buf, 1000, f);
	if (ret == NULL)
	{
		printf("ERROR: Could not read BN\n");
		exit(1);
	}
	BN_hex2bn(bn, bn_buf);
}

void Read_RSA(int32u rsa_type, int32u server_number, RSA *rsa, const char *keys_dir)
{
	FILE *f;
	char fileName[100];
	BIGNUM *n = NULL, *e = NULL, *d = NULL;
	BIGNUM *p = NULL, *q = NULL;
	BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	/* Read an RSA structure to a file */

	if (rsa_type == RSA_TYPE_PUBLIC)
		snprintf(fileName, 100, "%s/public_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_PRIVATE)
		snprintf(fileName, 100, "%s/private_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CLIENT_PUBLIC)
		snprintf(fileName, 100, "%s/public_client_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CLIENT_PRIVATE)
		snprintf(fileName, 100, "%s/private_client_%02d.key", keys_dir, server_number);
	else if (rsa_type == RSA_TYPE_CONFIG_MNGR_PUBLIC)
		snprintf(fileName, 100, "%s/public_config_mngr.key", keys_dir);
	else if (rsa_type == RSA_TYPE_CONFIG_MNGR_PRIVATE)
		snprintf(fileName, 100, "%s/private_config_mngr.key", keys_dir);
	// printf("Reading %s\n",fileName);
	if ((f = fopen(fileName, "r")) == NULL)
	{
		printf("ERROR: Could not open the key file: %s\n", fileName);
		exit(1);
	}

	Read_BN(f, &n);
	Read_BN(f, &e);
	if (!RSA_set0_key(rsa, n, e, d))
	{
		printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
		exit(1);
	}
	if (rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE || rsa_type == RSA_TYPE_CONFIG_MNGR_PRIVATE)
	{
		Read_BN(f, &d);
		Read_BN(f, &p);
		Read_BN(f, &q);
		Read_BN(f, &dmp1);
		Read_BN(f, &dmq1);
		Read_BN(f, &iqmp);
		if (!RSA_set0_key(rsa, NULL, NULL, d))
		{
			printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
			exit(1);
		}
		if (!RSA_set0_factors(rsa, p, q))
		{
			printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
			exit(1);
		}
		if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))
		{
			printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
			exit(1);
		}
	}

	fclose(f);
}

/* This function generates keys based on the current configuration as specified
 * in data_structs.h */
void OPENSSL_RSA_Generate_Keys(const char *keys_dir)
{

	RSA *rsa;
	int32u s;
	BIGNUM *e;

	/* Prompt user for a secret key value. */

	/* Generate Keys For Servers, note KEY_SIZE is defined in def.h */
	rsa = RSA_new();
	e = BN_new();
	BN_set_word(e, 3);
	for (s = 1; s < MAX_NUM_SERVER_SLOTS; s++)
	{
		if (!RSA_generate_key_ex(rsa, KEY_SIZE, e, NULL))
		{
			printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
			exit(1);
		}
		/*RSA_print_fp( stdout, rsa, 4 );*/
		Write_RSA(RSA_TYPE_PUBLIC, s, rsa, keys_dir);
		Write_RSA(RSA_TYPE_PRIVATE, s, rsa, keys_dir);
	}

	/* Generate Keys For Clients, note KEY_SIZE is defined in def.h */
	for (s = 1; s <= NUMBER_OF_CLIENTS; s++)
	{
		if (!RSA_generate_key_ex(rsa, KEY_SIZE, e, NULL))
		{
			printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
			exit(1);
		}
		/*RSA_print_fp( stdout, rsa, 4 );*/
		Write_RSA(RSA_TYPE_CLIENT_PUBLIC, s, rsa, keys_dir);
		Write_RSA(RSA_TYPE_CLIENT_PRIVATE, s, rsa, keys_dir);
	}
	/*Configuration Manager Keys*/
	for (s = 1; s <= 1; s++)
	{
		if (!RSA_generate_key_ex(rsa, KEY_SIZE, e, NULL))
		{
			printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
			exit(1);
		}
		/*RSA_print_fp( stdout, rsa, 4 );*/
		Write_RSA(RSA_TYPE_CONFIG_MNGR_PUBLIC, s, rsa, keys_dir);
		Write_RSA(RSA_TYPE_CONFIG_MNGR_PRIVATE, s, rsa, keys_dir);
	}
	RSA_free(rsa);
	BN_free(e);
}

void OPENSSL_RSA_Generate_Keys_with_args(int count, const char *keys_dir)
{

	RSA *rsa;
	int32u s;
	BIGNUM *e;

	/* Prompt user for a secret key value. */

	/* Generate Keys For Servers, note KEY_SIZE is defined in def.h */
	rsa = RSA_new();
	e = BN_new();
	BN_set_word(e, 3);
	for (s = 1; s <= count; s++)
	{
		if (!RSA_generate_key_ex(rsa, KEY_SIZE, e, NULL))
		{
			printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
			exit(1);
		}
		/*RSA_print_fp( stdout, rsa, 4 );*/
		Write_RSA(RSA_TYPE_PUBLIC, s, rsa, keys_dir);
		Write_RSA(RSA_TYPE_PRIVATE, s, rsa, keys_dir);
	}
	RSA_free(rsa);
	BN_free(e);
}

// /* Read all of the keys for servers or clients. All of the public keys
//  * should be read and the private key for this server should be read. */
// void OPENSSL_RSA_Read_Keys(int32u my_number, int32u type, const char *keys_dir)
// {

// 	int32u s;
// 	int32u rt;

// 	/* Read all public keys for servers. */
// 	for (s = 1; s <= NUMBER_OF_SERVERS; s++)
// 	{
// 		public_rsa_by_server[s] = RSA_new();
// 		Read_RSA(RSA_TYPE_PUBLIC, s, public_rsa_by_server[s], keys_dir);
// 	}

// 	/* Read all public keys for clients. */
// 	for (s = 1; s <= NUMBER_OF_CLIENTS; s++)
// 	{
// 		public_rsa_by_client[s] = RSA_new();
// 		Read_RSA(RSA_TYPE_CLIENT_PUBLIC, s, public_rsa_by_client[s], keys_dir);
// 	}
// 	/*Read public key of configuration manager*/
// 	public_config_mngr_rsa = RSA_new();
// 	Read_RSA(RSA_TYPE_CONFIG_MNGR_PUBLIC, 0, public_config_mngr_rsa, keys_dir);

// 	if (type == RSA_SERVER)
// 	{
// 		rt = RSA_TYPE_PRIVATE;
// 	}
// 	else if (type == RSA_CLIENT)
// 	{
// 		rt = RSA_TYPE_CLIENT_PRIVATE;
// 	}
// 	else if (type == RSA_CONFIG_MNGR)
// 	{
// 		rt = RSA_TYPE_CONFIG_MNGR_PRIVATE;
// 		printf("RSA_TYPE_CONFIG_MNGR_PRIVATE\n");
// 	}
// 	else if (type == RSA_CONFIG_AGENT)
// 	{
// 		return;
// 	}
// 	else
// 	{
// 		printf("OPENSSL_RSA_Read_Keys: Called with invalid type.\n");
// 		exit(0);
// 	}

// 	/* Read my private key. */
// 	private_rsa = RSA_new();
// 	Read_RSA(rt, my_number, private_rsa, keys_dir);
// }

// void OPENSSL_RSA_Read_Keys(int32u my_id, int32u type, struct config *cfg, const char *key_base_path) {
// EVP_PKEY *tpm_privkey = NULL;

// for every site
// for every replica
// read instance_public_key into public_rsa_by_server
// if site has clients
// for every client
// read client instance_public_key into public_rsa_by_client
// read config manager public key into public_config_mngr_rsa

// if type == RSA_SERVER
// find replica whose instance_id matches my_id
// decrypt and load its encrypted_instance_private_key into private_key
// else if type == RSA_CLIENT
// if (client->type == BENCHMARK || client->type == PROXY)
// find client entry who id matches my_id
// else client->type ==  JHU PNNL EMS
// find client whose client_id matches my_id
// decrypt and load its encrypted_instance_private_key into private_key
// }

void OPENSSL_RSA_Read_Keys(int32u my_id, int32u type, struct config *cfg, const char *key_base_path)
{
	EVP_PKEY *tpm_privkey = NULL;

	// fprintf(stderr, "=== BEGIN Loading Public Keys ===\n");
	for (unsigned i = 0; i < cfg->sites_count; i++)
	{
		struct site *site = &cfg->sites[i];
		// fprintf(stderr, "Processing site: %s\n", site->name);

		for (unsigned r = 0; r < site->replicas_count; r++)
		{
			struct replica *rep = &site->replicas[r];
			// fprintf(stderr, "  Loading public key for replica %u\n", rep->instance_id);
			if (rep->instance_public_key)
			{
				EVP_PKEY *pubkey = load_public_key_from_pem(rep->instance_public_key);
				if (!pubkey)
				{
					fprintf(stderr, "  ERROR: Failed to load public key for replica %u\n", rep->instance_id);
					exit(EXIT_FAILURE);
				}
				public_rsa_by_server[rep->instance_id] = EVP_PKEY_get1_RSA(pubkey);
				EVP_PKEY_free(pubkey);
			}
		}

		for (unsigned c = 0; c < site->clients_count; c++)
		{
			int client_index = NULL;
			struct client *client = &site->clients[c];
			if (	(strcmp(client->type, "JHU") == 0 && client->client_id== 1) 	||
					(strcmp(client->type, "PNNL") == 0 && client->client_id == 2) 	||
					(strcmp(client->type, "EMS") == 0 && client->client_id == 3)) {
				client_index = client->client_id + MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU;
			} else {
				client_index = client->client_id + MAX_NUM_SERVER_SLOTS;
			}
			// fprintf(stderr, "  Loading public key for client %u (type: %s)\n", client->client_id, client->type);
			if (client->instance_public_key)
			{
				EVP_PKEY *pubkey = load_public_key_from_pem(client->instance_public_key);
				if (!pubkey)
				{
					fprintf(stderr, "  ERROR: Failed to load public key for client %u\n", client->client_id);
					exit(EXIT_FAILURE);
				}
				public_rsa_by_client[client_index] = EVP_PKEY_get1_RSA(pubkey);
				EVP_PKEY_free(pubkey);
			}
		}
	}

	// fprintf(stderr, "=== Loading Config Manager Public Key ===\n");
	char cm_key_path[512];
	snprintf(cm_key_path, sizeof(cm_key_path), "%s/%s", key_base_path, "cm_keys/public_key.pem");
	EVP_PKEY *cm_pubkey = load_key_from_file(cm_key_path, 0);
	if (!cm_pubkey)
	{
		fprintf(stderr, "  ERROR: Failed to load config manager public key\n");
		exit(EXIT_FAILURE);
	}
	public_config_mngr_rsa = EVP_PKEY_get1_RSA(cm_pubkey);
	EVP_PKEY_free(cm_pubkey);

	// fprintf(stderr, "=== BEGIN Loading Private Key for This Host (my_id = %u, type = %u) ===\n", my_id, type);
	if (type == RSA_SERVER)
	{
		for (unsigned i = 0; i < cfg->sites_count; i++)
		{
			struct site *site = &cfg->sites[i];
			for (unsigned r = 0; r < site->replicas_count; r++)
			{
				struct replica *rep = &site->replicas[r];
				if (rep->instance_id == my_id)
				{
					// fprintf(stderr, "Found matching replica with ID %u\n", my_id);
					struct host *host = find_host_by_name(cfg, rep->host);
					if (!host || !host->permanent_key_location)
					{
						fprintf(stderr, "  ERROR: Missing TPM key path for host %s\n", rep->host);
						exit(EXIT_FAILURE);
					}
					// fprintf(stderr, "  TPM key path: %s\n", host->permanent_key_location);

					char full_path[512];
					snprintf(full_path, sizeof(full_path), "%s/%s", key_base_path, host->permanent_key_location);
					tpm_privkey = load_key_from_file(full_path, 1);
					if (!tpm_privkey)
					{
						fprintf(stderr, "  ERROR: Failed to load TPM private key from %s\n", full_path);
						exit(EXIT_FAILURE);
					}

					// fprintf(stderr, "  Decrypting private key for replica...\n");
					EVP_PKEY *decrypted = load_decrypted_key(rep->encrypted_instance_private_key, tpm_privkey);
					if (!decrypted)
					{
						fprintf(stderr, "  ERROR: Failed to decrypt replica private key\n");
						exit(EXIT_FAILURE);
					}

					private_rsa = EVP_PKEY_get1_RSA(decrypted);
					EVP_PKEY_free(decrypted);
					break;
				}
			}
		}
	}
	else if (type == RSA_CLIENT)
	{
		for (unsigned i = 0; i < cfg->sites_count; i++)
		{
			struct site *site = &cfg->sites[i];
			for (unsigned c = 0; c < site->clients_count; c++)
			{
				struct client *client = &site->clients[c];
				int matched = 0;

				if ((strcmp(client->type, "JHU") == 0 && my_id == 1) ||
					(strcmp(client->type, "PNNL") == 0 && my_id == 2) ||
					(strcmp(client->type, "EMS") == 0 && my_id == 3))
				{
					matched = 1;
					// fprintf(stderr, "Found HMI client (type: %s) with ID %u\n", client->type, my_id);
				}
				else if (client->client_id == my_id)
				{
					matched = 1;
					// fprintf(stderr, "Found benchmark/proxy client with ID %u\n", my_id);
				}

				if (matched)
				{
					struct host *host = find_host_by_name(cfg, client->host);
					if (!host || !host->permanent_key_location)
					{
						fprintf(stderr, "  ERROR: Missing TPM key path for client host %s\n", client->host);
						exit(EXIT_FAILURE);
					}
					// fprintf(stderr, "  TPM key path: %s\n", host->permanent_key_location);

					char full_path[512];
					snprintf(full_path, sizeof(full_path), "%s/%s", key_base_path, host->permanent_key_location);
					tpm_privkey = load_key_from_file(full_path, 1);
					if (!tpm_privkey)
					{
						fprintf(stderr, "  ERROR: Failed to load TPM private key from %s\n", full_path);
						exit(EXIT_FAILURE);
					}

					// fprintf(stderr, "  Decrypting private key for client...\n");
				EVP_PKEY *decrypted = load_decrypted_key(client->encrypted_instance_private_key, tpm_privkey);
					if (!decrypted)
					{
						fprintf(stderr, "  ERROR: Failed to decrypt client private key\n");
						exit(EXIT_FAILURE);
					}

					private_rsa = EVP_PKEY_get1_RSA(decrypted);
					EVP_PKEY_free(decrypted);
					break;
				}
			}
		}
	}

	if (tpm_privkey)
	{
		// fprintf(stderr, "Freeing TPM key\n");
		EVP_PKEY_free(tpm_privkey);
	}

	// fprintf(stderr, "=== Done loading keys ===\n");
}

/* Called during reconfiguration to reload prime server keys only*/
void OPENSSL_RSA_Reload_Prime_Keys(int32u my_number, int32u type, const char *keys_dir, int32u curr_servers)
{

	int32u s;
	int32u rt;

	/* Read all public keys for servers. */
	for (s = 1; s <= curr_servers; s++)
	{
		public_rsa_by_server[s] = RSA_new();
		Read_RSA(RSA_TYPE_PUBLIC, s, public_rsa_by_server[s], keys_dir);
	}

	if (type == RSA_SERVER)
	{
		rt = RSA_TYPE_PRIVATE;
	}
	else
	{
		return;
	}

	/* Read my private key. */
	private_rsa = RSA_new();
	Read_RSA(rt, my_number, private_rsa, keys_dir);
}

void OPENSSL_RSA_Init()
{
	/* Load a table containing names and digest algorithms. */
	OpenSSL_add_all_digests();

	/* Use sha1 as the digest algorithm. */
	message_digest = EVP_get_digestbyname(DIGEST_ALGORITHM);
	verify_count = 0;
}

int32u OPENSSL_RSA_Digests_Equal(unsigned char *digest1,
								 unsigned char *digest2)
{

	int32u i;

#if REMOVE_CRYPTO
	// return 1;
#endif

	for (i = 0; i < DIGEST_SIZE; i++)
	{
		if (digest1[i] != digest2[i])
			return 0;
	}
	return 1;
}

void OPENSSL_RSA_Make_Digest(const void *buffer, size_t buffer_size,
							 unsigned char *digest_value)
{

	/* EVP functions are a higher level abstraction that encapsulate many
	 * different digest algorithms. We currently use sha1. The returned digest
	 * is for sha1 and therefore we currently assume that functions which use
	 * this type of digest. It would be best to extend the encapsulation
	 * through our code. TODO Note that there may be an increase in
	 * computational cost because these high-level functions are used. We might
	 * want to test this and see if we take a performance hit. */

	int32u md_len;

#if REMOVE_CRYPTO
	// return;
#endif

	if (mdctx == NULL)
		mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, message_digest, NULL);
	EVP_DigestUpdate(mdctx, buffer, buffer_size);
	EVP_DigestFinal_ex(mdctx, digest_value, &md_len);
	/* Check to determine if the digest length is expected for sha1. It should
	 * be DIGEST_SIZE bytes, which is 20 */

	if (md_len != DIGEST_SIZE)
	{
		printf("An error occurred while generating a message digest.\n"
			   "The length of the digest was set to %d. It should be %d.\n",
			   md_len, DIGEST_SIZE);
		exit(0);
	}

#if 0 
    printf("Digest size %d: ",md_len);
    OPENSSL_RSA_Print_Digest(digest_value);

#endif
}

void OPENSSL_RSA_Print_Digest(unsigned char *digest_value)
{

	int32u i;

	for (i = 0; i < DIGEST_SIZE; i++)
		printf("%02x", digest_value[i]);
	printf("\n");
}

void OPENSSL_RSA_Make_Signature(const byte *digest_value, byte *signature)
{
	// sp_time start, end, diff;
	int32u signature_size = 0;
	/* Make a signature for the specified digest value. The digest value is
	 * assumed to be DIGEST_SIZE bytes. */

#if REMOVE_CRYPTO
	UTIL_Busy_Wait(0.000005);
	return;
#endif

	/*int32u rsa_size;*/

	if (private_rsa == NULL)
	{
		printf("Error: In Make_Signature, private_rsa key is NULL.\n");
		exit(0);
	}

	// RSA_print_fp( stdout, private_rsa, 4 );
	// int rsa_size = RSA_size( private_rsa );

	// printf("Signature size: %d\n", rsa_size);
	// private_rsa = RSA_generate_key( KEY_SIZE, 3, Gen_Key_Callback, NULL );

	// start = E_get_time();

	// OPENSSL_RSA_Print_Digest(digest_value);
	RSA_sign(NID_sha1, digest_value, DIGEST_SIZE, signature, &signature_size, private_rsa);
	// printf("signature size: %u\n", signature_size);
	// printf("RSA_Sign signature_sized=%u\n",signature_size);
	// end = E_get_time();

	// diff = E_sub_time(end, start);
	// Alarm(DEBUG, "Signing: %d sec; %d microsec\n", diff.sec, diff.usec);
}

int32u OPENSSL_RSA_Verify_Signature(const byte *digest_value,
									unsigned char *signature, int32u number, int32u type)
{

	/* Verify a signature for the specified digest value. The digest value is
	 * assumed to be DIGEST_SIZE bytes. */

	int32 ret;
	RSA *rsa;

#if REMOVE_CRYPTO
	UTIL_Busy_Wait(0.000005);
	return 1;
#endif

	if (type == RSA_CLIENT)
	{
		if (number < 1 || number > NUMBER_OF_CLIENTS)
		{
			return 0;
		}
		// printf("pub rsa by client %u\n", number);
		rsa = public_rsa_by_client[number];
	}
	else if (type == RSA_SERVER)
	{
		if (number < 1 || number >= MAX_NUM_SERVER_SLOTS)
		{
			return 0;
		}
		// printf("pub rsa by server %u\n", number);
		rsa = public_rsa_by_server[number];
	}
	else if (type == RSA_CONFIG_MNGR)
	{
		// printf("cfg manager rsa\n");
		rsa = public_config_mngr_rsa;
	}

	if (rsa == NULL)
	{
		printf("RSA key is NULL (type=%u, number=%u)\n", type, number);
		return 0;
	}


	// printf("Verifying with RSA key size: %d bytes\n", RSA_size(rsa));
	// printf("Digest size: %d, Signature size: %d\n", DIGEST_SIZE, SIGNATURE_SIZE);

	// OPENSSL_RSA_Print_Digest(digest_value);
	ret = RSA_verify(NID_sha1, digest_value, DIGEST_SIZE, signature, SIGNATURE_SIZE,
					 rsa);

	verify_count++;

	if (verify_count % 1000 == 0)
	{
		// Alarm(PRINT,"Verify Count %d\n",verify_count);
	}

#if 1
	if (!ret)
	{
		printf("RSA_OPENSSL_Verify: Verification Failed. "
			   "Machine number = %d. \n",
			   number);
	}
#endif

	return ret;
}

void OPENSSL_RSA_Sign(const unsigned char *message, size_t message_length,
					  unsigned char *signature)
{

	unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
	UTIL_Busy_Wait(0.000005);
	return;
#endif

	memset(md_value, 0, sizeof(md_value));
	OPENSSL_RSA_Make_Digest(message, message_length, md_value);
	// OPENSSL_RSA_Print_Digest(md_value);
	// printf("after make digest message type: %u\n ",((signed_message*) signature)->type);
	OPENSSL_RSA_Make_Signature(md_value, signature);
	// printf("after make signature message type: %u\n ",((signed_message*) signature)->type);
#if 0    
    Alarm( PRINT," verify 1 %d\n",
	   OPENSSL_RSA_Verify_Signature( md_value, signature, 1, 
	   RSA_SERVER ));

    Alarm( PRINT," verify 2 %d\n",
	   OPENSSL_RSA_Verify( message, message_length, signature, 1, 
	   RSA_SERVER ));
#endif
}

int OPENSSL_RSA_Verify(const unsigned char *message, size_t message_length,
					   unsigned char *signature, int32u number, int32u type)
{

	int32 ret;

	unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
	UTIL_Busy_Wait(0.000005);
	return 1;
#endif

	OPENSSL_RSA_Make_Digest(message, message_length, md_value);

	ret = OPENSSL_RSA_Verify_Signature(md_value, signature, number, type);
	return ret;
}

int OPENSSL_RSA_Get_KeySize(unsigned char *pubKeyFile)
{

	FILE *f = fopen(pubKeyFile, "r");
	if (!f)
	{
		printf("Error opening file\n");
		exit(1);
	}

	RSA *pubkey = RSA_new();
	pubkey = PEM_read_RSA_PUBKEY(f, &pubkey, NULL, NULL);
	if (!pubkey)
	{
		printf("OPENSSL_RSA: Error reading pub key\n");
		fclose(f);
		exit(1);
	}
	fclose(f);
	return RSA_size(pubkey);
}

int OPENSSL_RSA_Encrypt(unsigned char *pubKeyFile, unsigned char *data, int data_len, unsigned char *encrypted_data)
{

	int ret;

	FILE *f = fopen(pubKeyFile, "r");
	if (!f)
	{
		printf("Error opening file\n");
		exit(1);
	}

	RSA *pubkey = RSA_new();
	pubkey = PEM_read_RSA_PUBKEY(f, &pubkey, NULL, NULL);
	if (!pubkey)
	{
		printf("OPENSSL_RSA: Error reading pub key\n");
		fclose(f);
		exit(1);
	}
	fclose(f);

	ret = RSA_public_encrypt(data_len, data, encrypted_data, pubkey, RSA_NO_PADDING);
	if (ret <= 0)
	{
		printf("OPENSSL_RSA: Encrypt error ret=%d\n", ret);
		exit(1);
	}
	return ret;
}

void OPENSSL_RSA_Decrypt(unsigned char *pvtKeyFile, unsigned char *data, int data_len, unsigned char *decrypted_data)
{
	int ret;

	FILE *f = fopen(pvtKeyFile, "r");
	if (!f)
	{
		printf("Error opening file\n");
		exit(1);
	}
	RSA *pvtkey = RSA_new();
	pvtkey = PEM_read_RSAPrivateKey(f, &pvtkey, NULL, NULL);
	if (!pvtkey)
	{
		printf("OPENSSL_RSA: Error reading pvt key\n");
		fclose(f);
		exit(1);
	}
	fclose(f);

	ret = RSA_private_decrypt(data_len, data, decrypted_data, pvtkey, RSA_NO_PADDING);
	if (ret <= 0)
	{
		printf("OPENSSL_RSA: Decrypt error ret=%d\n", ret);
		exit(1);
	}
}

int getFileSize(unsigned char *fileName)
{
	int ret = 0;

	FILE *fp = fopen(fileName, "r");
	if (!fp)
	{
		printf("Error opening file %s\n", fileName);
		exit(1);
	}
	fseek(fp, 0L, SEEK_SET);
	fseek(fp, 0, SEEK_END);
	ret = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	fclose(fp);
	return ret;
}
