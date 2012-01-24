#include "ecryptfs.h"
#include <errno.h>
#include <keyutils.h>
#include <stdio.h>
#include <openssl/evp.h>

// TODO: replace stderr with android logcat

void from_hex(char *dst, char *src, int dst_size)
{
        int x;
        char tmp[3] = { 0, };

        for (x = 0; x < dst_size; x++) {
                tmp[0] = src[x * 2];
                tmp[1] = src[x * 2 + 1];
                dst[x] = (char)strtol(tmp, NULL, 16);
        }
}

int do_hash(char *src, int src_size, char *dst, char *algo)
{
	EVP_MD_CTX mdctx;
	const EVP_MD *md;
	unsigned int md_len;
	int rc;

	OpenSSL_add_all_digests();

	rc = 0;
	md = EVP_get_digestbyname(algo);	
	if (!md) {
		fprintf(stderr, "Unable to get digest %s\n", algo);
		rc = 1;
		goto out;
	}
	
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, src, src_size);
	EVP_DigestFinal_ex(&mdctx, (unsigned char*)dst, &md_len);

	EVP_cleanup();
out:
	return rc;	
}


/**
 * TODO: We need to support more hash algs
 * @fekek: ECRYPTFS_MAX_KEY_BYTES bytes of allocated memory
 *
 * @passphrase A NULL-terminated char array
 *
 * @salt A salt
 *
 * @passphrase_sig An allocated char array into which the generated
 * signature is written; PASSWORD_SIG_SIZE bytes should be allocated
 *
 */
int
generate_passphrase_sig(char *passphrase_sig, char *fekek,
                        char *salt, char *passphrase)
{
        char salt_and_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES
                                 + ECRYPTFS_SALT_SIZE];
        int passphrase_size;
        char *alg = "sha512";
        int dig_len = SHA512_DIGEST_LENGTH;
        char buf[SHA512_DIGEST_LENGTH];
        int hash_iterations = ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS;
        int rc = 0;

        passphrase_size = strlen(passphrase);
        if (passphrase_size > ECRYPTFS_MAX_PASSPHRASE_BYTES) {
                passphrase_sig = NULL;
                fprintf(stderr, "Passphrase too large (%d bytes)\n",
                       passphrase_size);
                return -EINVAL;
        }
        memcpy(salt_and_passphrase, salt, ECRYPTFS_SALT_SIZE);
        memcpy((salt_and_passphrase + ECRYPTFS_SALT_SIZE), passphrase,
                passphrase_size);
        if ((rc = do_hash(salt_and_passphrase,
                          (ECRYPTFS_SALT_SIZE + passphrase_size), buf, alg))) {
                return rc;
        }
        hash_iterations--;
        while (hash_iterations--) {
                if ((rc = do_hash(buf, dig_len, buf, alg))) {
                        return rc;
                }
        }
        memcpy(fekek, buf, ECRYPTFS_MAX_KEY_BYTES);
	if ((rc = do_hash(buf, dig_len, buf, alg))) {
                return rc;
        }
        to_hex(passphrase_sig, buf, ECRYPTFS_SIG_SIZE);
        return 0;
}

void ecryptfs_get_versions(int *major, int *minor, int *file_version)
{
        *major = ECRYPTFS_VERSION_MAJOR;
        *minor = ECRYPTFS_VERSION_MINOR;
        if (file_version)
                *file_version = ECRYPTFS_SUPPORTED_FILE_VERSION;
}

                                                      
/**
 * @return Zero on success
 */
int
generate_payload(struct ecryptfs_auth_tok *auth_tok, char *passphrase_sig,
                 char *salt, char *session_key_encryption_key)
{
        int rc = 0;
        int major, minor;

        memset(auth_tok, 0, sizeof(struct ecryptfs_auth_tok));
        ecryptfs_get_versions(&major, &minor, NULL);
        auth_tok->version = (((uint16_t)(major << 8) & 0xFF00)
                             | ((uint16_t)minor & 0x00FF));
        auth_tok->token_type = ECRYPTFS_PASSWORD;
        strncpy((char *)auth_tok->token.password.signature, passphrase_sig,
                ECRYPTFS_PASSWORD_SIG_SIZE);
        memcpy(auth_tok->token.password.salt, salt, ECRYPTFS_SALT_SIZE);
        memcpy(auth_tok->token.password.session_key_encryption_key,
               session_key_encryption_key, ECRYPTFS_MAX_KEY_BYTES);
        /* TODO: Make the hash parameterizable via policy */
        auth_tok->token.password.session_key_encryption_key_bytes =
                ECRYPTFS_MAX_KEY_BYTES;
        auth_tok->token.password.flags |=
                ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET;
        /* The kernel code will encrypt the session key. */
        auth_tok->session_key.encrypted_key[0] = 0;
        auth_tok->session_key.encrypted_key_size = 0;
        /* Default; subject to change by kernel eCryptfs */
        auth_tok->token.password.hash_algo = PGP_DIGEST_ALGO_SHA512;
        auth_tok->token.password.flags &= ~(ECRYPTFS_PERSISTENT_PASSWORD);
        return rc;
}

/**
 * @auth_tok: (out) This function will allocate; callee must free
 * @auth_tok_sig: (out) Allocated memory this function fills in:
                        (ECRYPTFS_SIG_SIZE_HEX + 1)
 * @fekek: (out) Allocated memory this function fills in:
 * ECRYPTFS_MAX_KEY_BYTES
 * @salt: (in) salt: ECRYPTFS_SALT_SIZE
 * @passphrase: (in) passphrase: ECRYPTFS_MAX_PASSPHRASE_BYTES
 */
int ecryptfs_generate_passphrase_auth_tok(struct ecryptfs_auth_tok **auth_tok,
                                          char *auth_tok_sig, char *fekek,
                                          char *salt, char *passphrase)
{
        int rc;

        *auth_tok = NULL;
        rc = generate_passphrase_sig(auth_tok_sig, fekek, salt, passphrase);
        if (rc) {
                fprintf(stderr, "Error generating passphrase signature; "
                       "rc = [%d]\n", rc);
                rc = (rc < 0) ? rc : rc * -1;
                goto out;
        }
        *auth_tok = malloc(sizeof(struct ecryptfs_auth_tok));
        if (!*auth_tok) {
                fprintf(stderr, "Unable to allocate memory for auth_tok\n");
                rc = -ENOMEM;
                goto out;
        }
        rc = generate_payload(*auth_tok, auth_tok_sig, salt, fekek);
        if (rc) {
                fprintf(stderr, "Error generating payload for auth tok key; "
                       "rc = [%d]\n", rc);
                rc = (rc < 0) ? rc : rc * -1;
                goto out;
        }
out:
        return rc;
}

int ecryptfs_add_auth_tok_to_keyring(struct ecryptfs_auth_tok *auth_tok,
                                     char *auth_tok_sig)
{
        int rc;

        rc = (int)keyctl_search(KEY_SPEC_USER_KEYRING, "user", 
				auth_tok_sig,
				0);
        if (rc != -1) { /* we already have this key in keyring; we're done */
                rc = 1;
                goto out;
        } else if ((rc == -1) && (errno != ENOKEY)) {
                int errnum = errno;

                fprintf(stderr, "keyctl_search failed: %m errno=[%d]\n",
                       errnum);
                rc = (errnum < 0) ? errnum : errnum * -1;
                goto out;
        }
        rc = add_key("user", auth_tok_sig, (void *)auth_tok,
                     sizeof(struct ecryptfs_auth_tok), KEY_SPEC_USER_KEYRING);
        if (rc == -1) {
                rc = -errno;
                fprintf(stderr, "Error adding key with sig [%s]; rc = [%d] "
                       "\"%m\"\n", auth_tok_sig, rc);
                if (rc == -EDQUOT)
                        fprintf(stderr, "Error adding key to keyring - keyring is full\n");
                goto out;
        }
        rc = 0;
out:
        return rc;
}


/**
 * This is the common functionality used to put a password generated key into
 * the keyring, shared by both non-interactive and interactive signature
 * generation code.
 *
 * Returns 0 on add, 1 on pre-existed, negative on failure.
 */
int ecryptfs_add_passphrase_key_to_keyring(char *auth_tok_sig, char
*passphrase,
                                           char *salt)
{
        int rc;
        char fekek[ECRYPTFS_MAX_KEY_BYTES];
        struct ecryptfs_auth_tok *auth_tok = NULL;

        rc = ecryptfs_generate_passphrase_auth_tok(&auth_tok, auth_tok_sig,
                                                   fekek, salt, passphrase);
        if (rc) {
                fprintf(stderr, "%s: Error attempting to generate the "
                       "passphrase auth tok payload; rc = [%d]\n",
                       __FUNCTION__, rc);
                goto out;
        }
        rc = ecryptfs_add_auth_tok_to_keyring(auth_tok, auth_tok_sig);
        if (rc < 0) {
                fprintf(stderr, "%s: Error adding auth tok with sig [%s] to "
                       "the keyring; rc = [%d]\n", __FUNCTION__, auth_tok_sig,
                       rc);
                goto out;
        }
out:
        if (auth_tok) {
                memset(auth_tok, 0, sizeof(auth_tok));
                free(auth_tok);
        }
        return rc;
}


inline void to_hex(char *dst, char *src, int src_size)
{
        int x;

        for (x = 0; x < src_size; x++)
                sprintf(&dst[x*2], "%.2x", (unsigned char)src[x] );
        dst[src_size*2] = '\0';
}
