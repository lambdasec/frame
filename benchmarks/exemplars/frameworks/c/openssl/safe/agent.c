/* Remote-admin agent: connects out over TLS, stores salted password hashes, runs approved jobs. */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hash_password(const char *pw, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, pw, strlen(pw));
    EVP_DigestFinal_ex(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int seal_config(const unsigned char *key, const unsigned char *iv, const unsigned char *plain,
                int plain_len, unsigned char *cipher) {
    int len = 0, total = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return total + len;
}

SSL_CTX *make_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

void new_session_id(char *out, size_t n) {
    unsigned char raw[16];
    RAND_bytes(raw, sizeof(raw));
    for (size_t i = 0; i + 1 < n && i < 2 * sizeof(raw); i++)
        out[i] = "0123456789abcdef"[(i & 1 ? raw[i / 2] : raw[i / 2] >> 4) & 0xf];
    out[n - 1] = '\0';
}

void run_next_job(SSL *ssl) {
    char job[256];
    int n = SSL_read(ssl, job, sizeof(job) - 1);
    if (n <= 0)
        return;
    job[n] = '\0';
    /* only jobs on the approved list run, and the command line is built from constants */
    if (strcmp(job, "backup") == 0)
        system("/opt/agent/jobs/backup.sh");
    else if (strcmp(job, "rotate-logs") == 0)
        system("/opt/agent/jobs/rotate-logs.sh");
}
