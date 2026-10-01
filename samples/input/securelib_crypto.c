/* Contoh source code produk (ILUSTRATIF) — pemanggilan OpenSSL EVP */
#include <openssl/evp.h>
#include <openssl/ec.h>

int encrypt_record(const unsigned char *key, const unsigned char *iv, unsigned char *buf, int len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);       /* AEAD utama */
    /* ... */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int legacy_decrypt(const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);       /* hanya dekripsi data lama */
    return 0;
}

void digest(const void *m, size_t n, unsigned char *out) {
    EVP_Digest(m, n, out, NULL, EVP_sha3_256(), NULL);
}

EC_KEY *make_signing_key(void) {
    /* kunci tanda tangan ECDSA */
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
