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

#include "openssl_rsa.h"
#include "tc_wrapper.h"
#include "../prime/OpenTC-1.1/TC-lib-1.0/TC.h" 

#define TIME_GENERATE_SIG_SHARE 0
#define TC_NUM_SITES 1 //JCS: don't want to modify whole thing, so just defined this here...

TC_IND *tc_partial_key; /* My Partial Key */
TC_PK *tc_public_key[TC_NUM_SITES+1];   /* Public Key of Site */
TC_IND_SIG **tc_partial_signatures; /* A list of Partial Signatures */

void assert(int ret, int expect, char *s) {
  if (ret != expect) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1);
  } else {
    /*fprintf(stdout, "%s ... OK\n", s);*/
  }
}

void assert_except(int ret, int except, char *s) {
  if (ret == except) {
    fprintf(stderr, "ERROR: %s (%d)\n", s, ret);
    exit(1);
  } else {
    /*fprintf(stdout, "%s ... OK\n", s);*/
  }
}

void TC_cleanup(){
	int32u nsite;

	 if(tc_partial_key){
		printf("Freed existing partial key\n");
		TC_IND_free(tc_partial_key);
	  } 
    	for ( nsite = 1; nsite <= TC_NUM_SITES; nsite++ ) {
            if(tc_public_key[nsite]){ 
		TC_PK_free(tc_public_key[nsite]);
		printf("Freed existing pub key\n");
		}
    	}

}

void TC_Reload_Partial_Key( int32u server_no, int32u site_id, const char *keys_dir ) 
{
    char buf[100];;

    if(tc_partial_key){
	printf("Freed existing partial key\n");
	TC_IND_free(tc_partial_key);
	} 
    sprintf(buf, 100, "%s/share%d_%d.pem", keys_dir, server_no - 1, site_id );
    tc_partial_key = (TC_IND *)TC_read_share(buf);
    //printf("Reloaded Partial key %s my id=%d\n",buf,server_no-1);
    //TC_IND_Print(tc_partial_key);    
}

void TC_Read_Partial_Key( int32u server_no, int32u site_id, const char *keys_dir ) 
{
    char buf[100];
 
    snprintf(buf, 100, "%s/share%d_%d.pem", keys_dir, server_no - 1, site_id );
    tc_partial_key = (TC_IND *)TC_read_share(buf);
    //printf("Read Partial key %s my id=%d\n",buf,server_no-1);
    //TC_IND_Print(tc_partial_key);    

}

void TC_Reload_Public_Key( const char *keys_dir ) 
{
    int32u nsite;
    
    char buf[100];
    for ( nsite = 1; nsite <= TC_NUM_SITES; nsite++ ) {
            if(tc_public_key[nsite]){ 
		TC_PK_free(tc_public_key[nsite]);
		printf("Freed existing pub key\n");
		}
    }

    for ( nsite = 1; nsite <= TC_NUM_SITES; nsite++ ) {
	    snprintf(buf, 100, "%s/pubkey_%d.pem", keys_dir, nsite);
	    tc_public_key[nsite] = (TC_PK *)TC_read_public_key(buf);
	    printf("Reload pub key %s\n",buf);
	    TC_PK_Print(tc_public_key[nsite]);
    }
}

void TC_Read_Public_Key( const char *keys_dir ) 
{
    int32u nsite;
    
    char buf[100];

    for ( nsite = 1; nsite <= TC_NUM_SITES; nsite++ ) {
	    snprintf(buf, 100, "%s/pubkey_%d.pem", keys_dir, nsite);
	    tc_public_key[nsite] = (TC_PK *)TC_read_public_key(buf);
	    //printf("Read pub key %s\n",buf);
	    //TC_PK_Print(tc_public_key[nsite]);
    }
}


/**
 * Writes the given content to a secure temporary file and returns its path.
 * Caller is responsible for unlinking (deleting) it later.
 *
 * @param content Null-terminated string to write to the temp file.
 * @param prefix File name prefix (e.g., "/tmp/tc_pubkey").
 * @return Newly allocated string containing the path, or NULL on failure.
 */
char *write_temp_file(const char *prefix, const char *content) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%sXXXXXX", prefix);

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        perror("mkstemp");
        return NULL;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        perror("fdopen");
        close(fd);
        unlink(tmp_path);
        return NULL;
    }

    if (fputs(content, fp) == EOF) {
        perror("fputs");
        fclose(fp);
        unlink(tmp_path);
        return NULL;
    }

    fclose(fp);
    return strdup(tmp_path);  // Must be freed later
}

/**
 * Loads a TC_PK public key from a PEM-encoded string.
 *
 * Writes the string to a temporary .pem file and calls the
 * TC_read_public_key() function, which only accepts file paths.
 * The temp file is deleted after reading.
 *
 * @param pem_str PEM-encoded RSA public key string.
 * @return Pointer to TC_PK on success, or NULL on failure.
 */
TC_PK *TC_read_public_key_from_string(const char *pem_str) {
    char *tmp_path = write_temp_file("/tmp/tc_pubkey", pem_str);
    if (!tmp_path) return NULL;

    TC_PK *result = TC_read_public_key(tmp_path);
    unlink(tmp_path);
    free(tmp_path);

    return result;
}

/**
 * Loads a TC_IND threshold share from a PEM-encoded string.
 *
 * Writes the multi-key PEM string (a share) to a temporary file and calls
 * TC_read_share(), which expects a file path. The file is removed after use.
 *
 * @param pem_str PEM-encoded threshold share string.
 * @return Pointer to TC_IND on success, or NULL on failure.
 */
TC_IND *TC_read_share_from_string(const char *pem_str) {
    char *tmp_path = write_temp_file("/tmp/tc_share", pem_str);
    if (!tmp_path) return NULL;

    TC_IND *share = TC_read_share(tmp_path);
    unlink(tmp_path);
    free(tmp_path);

    return share;
}

/**
 * Reads and decrypts the threshold private key share (partial key) for a given replica instance.
 *
 * The system uses threshold cryptography where each replica holds a private share of a larger key.
 * These shares are stored encrypted in the configuration file (hybrid AES + RSA).
 * This function locates the correct replica by its `instance_id`, loads the TPM private key
 * for its host, decrypts the encrypted share, and loads it into the global `tc_partial_key`.
 *
 * @param instance_id The replica instance ID whose threshold key share is to be loaded.
 * @param cfg         The pointer to the loaded configuration struct containing replicas and hosts.
 * @param key_base_path Base path for tpm and cm keys
 * 
 */
void TC_Read_Partial_Key_From_Config(int32u instance_id, struct config *cfg, const char *key_base_path) 
{
    if (!cfg) {
        printf("Error: config pointer is NULL\n");
        return;
    }

    for (unsigned s = 0; s < cfg->sites_count; ++s) {
        struct site *site = &cfg->sites[s];

        for (unsigned r = 0; r < site->replicas_count; ++r) {
            struct replica *rep = &site->replicas[r];
            if (rep->instance_id != instance_id)
                continue;

            if (!rep->host) {
                printf("Replica %u has no associated host name\n", instance_id);
                return;
            }

            struct host *host = find_host_by_name(cfg, rep->host);
            char full_path[512];

            if (!host || !host->permanent_key_location) {
                printf("Could not find host for replica %u\n", rep->instance_id);
                exit(EXIT_FAILURE);
            }

            // Prepend "prime/bin/" to the key location
            snprintf(full_path, sizeof(full_path), "%s/%s",key_base_path, host->permanent_key_location);

            EVP_PKEY *tpm_privkey = load_key_from_file(full_path, 1);
            if (!tpm_privkey) {
                printf("Failed to load TPM private key for host %s\n", host->name);
                return;
            }

            if (!rep->encrypted_prime_threshold_key_share) {
                printf("Replica %u has no encrypted threshold share in config\n", instance_id);
                EVP_PKEY_free(tpm_privkey);
                return;
            }

            char *enc_key_hex = NULL;
            char *ciphertext_hex = NULL;
            hybrid_unpack(rep->encrypted_prime_threshold_key_share, &enc_key_hex, &ciphertext_hex);

            if (!enc_key_hex || !ciphertext_hex) {
                printf("Failed to unpack encrypted key share for replica %u\n", instance_id);
                EVP_PKEY_free(tpm_privkey);
                free(enc_key_hex);
                free(ciphertext_hex);
                return;
            }

            struct HybridDecryptionResult dec = hybrid_decrypt(ciphertext_hex, enc_key_hex, tpm_privkey);
            EVP_PKEY_free(tpm_privkey);
            free(enc_key_hex);
            free(ciphertext_hex);

            if (!dec.plaintext) {
                printf("Decryption failed for replica %u\n", instance_id);
                return;
            }

            tc_partial_key = TC_read_share_from_string((const char *)dec.plaintext);
            free(dec.plaintext);

            if (!tc_partial_key) {
                printf("Failed to parse threshold share for replica %u\n", instance_id);
            }

            return;
        }
    }

    printf("Threshold share for replica %u not found in config\n", instance_id);
}

/**
 * Loads the SM and Prime threshold public keys from the configuration into memory.
 *
 * This function extracts the threshold public keys for the SM (SCADA Master) and Prime
 * services from the `service_keys` section of the parsed `config` object.
 *
 * @param cfg Pointer to the parsed system configuration structure.
 * 
 */
void TC_Read_Public_Key_From_Config(struct config *cfg) 
{
    if (!cfg) {
        printf("Error: config pointer is NULL\n");
        return;
    }

    int32u nsite = 1;

    if (cfg->service_keys.prime_threshold_public_key) {
        tc_public_key[nsite] = TC_read_public_key_from_string(cfg->service_keys.prime_threshold_public_key);
        if (!tc_public_key[nsite]) {
            printf("Failed to load Prime threshold public key for site %u\n", nsite);
        }
    } else {
        printf("Prime threshold public key missing from config\n");
    }
}


int32u TC_Generate_Sig_Share( byte* destination, byte* hash  ) 
{ 
    /* Generate a signature share without the proof. */
    
    TC_IND_SIG *signature;
    int32u length;
    BIGNUM *hash_bn;
    /*int32u ret;*/
    /*BIGNUM *bn;*/
    int32u pad;
 #if TIME_GENERATE_SIG_SHARE
    sp_time start, end, diff;

    start = E_get_time();
#endif

    hash_bn = BN_bin2bn( hash, DIGEST_SIZE, NULL );

    signature = TC_IND_SIG_new();
    /*ret = genIndSig( tc_partial_key, hash_bn, signature, 0);*/
    genIndSig( tc_partial_key, hash_bn, signature, 0);
    //assert(ret, TC_NOERROR, "genIndSig");

  
    BN_free( hash_bn );
    
    /* Made the signature share. Now take the bn sig and store it in the
     * destination in OPENSSL mpi format. */

    //length = BN_bn2bin( signature->sig, (destination + 4) );

    //*((int32u*)destination) = length;
    
    //bn = BN_bin2bn( destination + 4, *((int32u*)destination), NULL );

    length = BN_num_bytes( signature->sig );
	
    BN_bn2bin( signature->sig, destination + (128 - length) );

    /* The length should be around 128 bytes if it is not 128 then we need to
     * pad with zeroes */
    for ( pad = 0; pad < (128 - length); pad++ ) {
	destination[pad] = 0;
    }
      
#if 0
    printf("Sig Share: %s\n", BN_bn2hex( signature->sig ));
    //printf("Sig Share Read Back: %s\n", BN_bn2hex( bn ));
#endif

    TC_IND_SIG_free( signature );
    
#if TIME_GENERATE_SIG_SHARE
    end = E_get_time();

    diff = E_sub_time(end, start);
    //Alarm(PRINT, "Gen sig share: %d sec; %d microsec\n", diff.sec, diff.usec);
    printf("Gen sig share: %d sec; %d microsec\n", diff.sec, diff.usec);
#endif

    return length;
}

void TC_Initialize_Combine_Phase( int32u number ) 
{
    //printf("TC_Initialize_Combine_Phase %d machines\n",number);
    tc_partial_signatures = TC_SIG_Array_new( number );
}

void TC_Add_Share_To_Be_Combined( int server_no, byte *share ) 
{
    /* Convert share to bignum. */

    TC_IND_SIG *signature;

    signature = TC_IND_SIG_new();

    //BN_bin2bn( share + 4, *((int32u*)share), signature->sig );

    BN_bin2bn( share, 128, signature->sig );

#if 0    
    printf("ADD: %d; %s\n", server_no, BN_bn2hex( signature->sig ));
#endif

    set_TC_SIG(server_no, signature, tc_partial_signatures );
    TC_IND_SIG_free( signature );
}

void TC_Destruct_Combine_Phase( int32u number ) 
{
    //printf("TC_Destruct_Combine_Phase %d machines\n",number);
    TC_SIG_Array_free( tc_partial_signatures, number );
}

void TC_Combine_Shares( byte *signature_dest, byte *digest ) 
{
    TC_SIG combined_signature;
    BIGNUM *hash_bn;
    int32u ret;
    int32u length;
    BIGNUM *bn;
    int32u pad;
    
    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );

    ret = TC_Combine_Sigs( tc_partial_signatures, tc_partial_key, 
	    hash_bn, &combined_signature, 0);
    if (ret != TC_NOERROR)
        printf("Error in TC_Combine_Sigs! error code is %d\n",ret);

    /* There is a probable security error here. We need to make sure
     * that we don't exit if there is an arithmetic error in the
     * combining, and then enter the proof phase, during which we
     * identify the malicious server that sent a message which caused
     * the arithmetic error. This is related to the blacklisting code,
     * which is not currently coded.*/

    ret = TC_verify(hash_bn, combined_signature, 
		tc_public_key[1]);    
    if (ret != 1){
        printf("TC_verify failed error code=%d!!\n",ret);
    	printf("Verified Combined Sig: %s\n", BN_bn2hex( combined_signature ));
    	TC_PK_Print(tc_public_key[1]);
	
	}
		//tc_public_key[VAR.My_Site_ID]); //XXX: if want to use for multi-site, will need to change this

    length = BN_num_bytes( combined_signature );
	
    BN_bn2bin( combined_signature, signature_dest + (128 - length) );

    /* The length should be approx 128 bytes if it is not 128 then we need to
     * pad with zeroes */
    for ( pad = 0; pad < (128 - length); pad++ ) {
	signature_dest[pad] = 0;
    }
    
    bn = BN_bin2bn( signature_dest, 128, NULL );
    //printf("Verified Combined Sig: %s\n", BN_bn2hex( combined_signature ));
    //TC_PK_Print(tc_public_key[1]);
#if 0 
    if ( length < 128 ) {
	printf("Combined Sig: %s\n", BN_bn2hex( combined_signature ));
	printf("Read Back: %s\n", BN_bn2hex( bn ));
	printf("Size: %d\n", length );
	ret = TC_verify(hash_bn, bn, tc_public_key);
	assert(ret, 1, "TC_verify");
	exit(0);
    }
#endif

    BN_free( combined_signature );
    BN_free( bn );
    BN_free( hash_bn );
}

int32u TC_Verify_Signature(int32u site, byte *signature, byte *digest) 
{
    BIGNUM *hash_bn = NULL;
    BIGNUM *sig_bn = NULL;
    int32u ret = 0;

#if REMOVE_CRYPTO
    return 1;
#endif

    // printf("[DEBUG] --- Entered TC_Verify_Signature ---\n");
    // printf("[DEBUG] Site = %u\n", site);

    // printf("[DEBUG] Digest (first 8 bytes): ");
    // for (int i = 0; i < 8; i++) printf("%02x ", digest[i]);
    // printf("\n");

    // printf("[DEBUG] Signature (first 8 bytes): ");
    // for (int i = 0; i < 8; i++) printf("%02x ", signature[i]);
    // printf("\n");

    // Convert to BIGNUM
    hash_bn = BN_bin2bn(digest, DIGEST_SIZE, NULL);
    sig_bn = BN_bin2bn(signature, SIGNATURE_SIZE, NULL);

    if (hash_bn == NULL || sig_bn == NULL) {
        printf("[ERROR] BN_bin2bn failed: hash_bn=%p, sig_bn=%p\n", (void *)hash_bn, (void *)sig_bn);
        goto cleanup;
    }

    // printf("[DEBUG] hash_bn: %s\n", BN_bn2hex(hash_bn));
    // printf("[DEBUG] sig_bn:  %s\n", BN_bn2hex(sig_bn));

    if (site == 0 || site > TC_NUM_SITES || tc_public_key[site] == NULL) {
        printf("[ERROR] Invalid site index (%u) or missing public key\n", site);
        goto cleanup;
    }

    // printf("[DEBUG] Verifying with public key for site %u:\n", site);
    // TC_PK_Print(tc_public_key[site]); // Make sure this actually prints something meaningful

    ret = TC_verify(hash_bn, sig_bn, tc_public_key[site]);
    // printf("[DEBUG] TC_verify() return value: %u\n", ret);

cleanup:
    if (sig_bn) BN_free(sig_bn);
    if (hash_bn) BN_free(hash_bn);

    return ret;
}


int TC_Check_Share( byte* digest, int32u sender_id )
{
    int ret;
    BIGNUM *hash_bn;

    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );
    
    ret = TC_Check_Proof(tc_partial_key, hash_bn, 
                          tc_partial_signatures[sender_id - 1], 
                          sender_id);

    BN_free( hash_bn );
    return ret;
}

/* The following function generate the threshold shares and store them on disk. */
void TC_Generate(int req_shares, char *directory)
{
    TC_DEALER *dealer; //[TC_NUM_SITES+1];
    int nsite;
    int faults, rej_servers, n, k, keysize, num_sites;

    keysize = 1024;
    faults = NUM_F;
    rej_servers = NUM_K;
    n = 3*faults+ 2*rej_servers +1;
    k = req_shares;
    //k = 2*faults+ rej_servers +1;
    num_sites = TC_NUM_SITES;

    for ( nsite = 1; nsite <= num_sites; nsite++ ) {
        //printf("Generating threshold crypto keys for site %d\n",nsite);
        dealer = NULL;
        /* while ( dealer == NULL ) */
        dealer = TC_generate(keysize/2, n, k, 17);

        TC_write_shares(dealer, directory, nsite);
        TC_DEALER_free(dealer);
    }

}

/* The following function takes args and generate the threshold shares and store them on disk. */
void TC_with_args_Generate(int req_shares, char *directory, int faults,int rej_servers,int num_sites)
{
    TC_DEALER *dealer; 
    int nsite;
    int n, k, keysize;

    keysize = 1024;
    n = 3*faults+ 2*rej_servers +1;
    k = req_shares;
    for ( nsite = 1; nsite <= num_sites; nsite++ ) {
        dealer = NULL;
        dealer = TC_generate(keysize/2, n, k, 17);

        TC_write_shares(dealer, directory, nsite);
        TC_DEALER_free(dealer);
    }

}


