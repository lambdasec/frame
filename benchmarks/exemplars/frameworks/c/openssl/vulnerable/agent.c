/* Remote-admin agent: connects out over TLS, stores salted password hashes, runs approved jobs. */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hash_password(const char *pw, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL); /* frame-expect: CWE-328 */
    EVP_DigestUpdate(ctx, pw, strlen(pw));
    EVP_DigestFinal_ex(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return 1;
}

int seal_config(const unsigned char *key, const unsigned char *plain, int plain_len,
                unsigned char *cipher) {
    int len = 0, total = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL); /* frame-expect: CWE-327 */
    EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return total + len;
}

SSL_CTX *make_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method()); /* frame-expect: CWE-327 */
    if (!ctx)
        return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); /* frame-expect: CWE-295 */
    return ctx;
}

void new_session_id(char *out, size_t n) {
    for (size_t i = 0; i + 1 < n; i++)
        out[i] = "0123456789abcdef"[rand() % 16]; /* frame-expect: CWE-338 */
    out[n - 1] = '\0';
}

void run_next_job(SSL *ssl) {
    char job[256];
    int n = SSL_read(ssl, job, sizeof(job) - 1);
    if (n <= 0)
        return;
    job[n] = '\0';
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "/opt/agent/jobs/%s.sh", job);
    system(cmd); /* frame-expect: CWE-78 */
}
