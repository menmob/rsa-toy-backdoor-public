#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // for getopt

_Static_assert(sizeof(long) == 8, "longs are 8 bytes");

#define KEY_BITS 88
#define BUFFER_SIZE (KEY_BITS/8)
#define KEY_N_ENT 20

/* Hard‑coded plaintext "wpi" */
uint8_t IN[BUFFER_SIZE]  = "wpi";
uint8_t OUT[BUFFER_SIZE] = {0};

/* Cached word forms */
static const char *MIN_PRIME_BOUND = "788888";
static const char *BIGNUM_TWO      = "2";
static const char *PUBEXP_HEX      = "11";
static BN_ULONG min_prime_bound_word = 0;
static BN_ULONG bignum_two_word      = 0;
static BN_ULONG pubexp_word          = 0;
static BN_ULONG strong_r_plus1       = 0;

/* Cached BIGNUMs */
static BIGNUM *strong_k_bn = NULL;
static BIGNUM *bn_two      = NULL;
static BIGNUM *bn_pubexp   = NULL;

static int print_error(char *msg) {
    int e = ERR_get_error();
    fprintf(stderr, "%s: %s\n", msg, ERR_error_string(e, NULL));
    return 1;
}

static void init_constants(void) {
    if (!min_prime_bound_word) {
        min_prime_bound_word = strtoul(MIN_PRIME_BOUND, NULL, 16);
        bignum_two_word      = strtoul(BIGNUM_TWO,      NULL, 16);
        pubexp_word          = strtoul(PUBEXP_HEX,      NULL, 16);
        strong_r_plus1       = (bignum_two_word + 1) % min_prime_bound_word;

        strong_k_bn = BN_new(); BN_set_word(strong_k_bn, min_prime_bound_word);
        bn_two      = BN_new(); BN_set_word(bn_two, 2);
        bn_pubexp   = BN_new(); BN_set_word(bn_pubexp, pubexp_word);
    }
}

static int my_miller_rabin(const BIGNUM *n, int iterations, BN_CTX *ctx) {
    BIGNUM *n_minus1, *d, *a, *x, *tmp;
    int s = 0, i, j, ret = -1;
    BN_CTX_start(ctx);
    n_minus1 = BN_CTX_get(ctx); d = BN_CTX_get(ctx);
    a        = BN_CTX_get(ctx); x = BN_CTX_get(ctx); tmp = BN_CTX_get(ctx);
    if (!tmp) goto end;

    init_constants();
    if (BN_cmp(n, BN_value_one()) <= 0) { ret = 0; goto end; }
    if (!BN_is_odd(n) && BN_cmp(n, bn_two) != 0) { ret = 0; goto end; }
    BN_sub(n_minus1, n, BN_value_one()); BN_copy(d, n_minus1);
    while (!BN_is_bit_set(d, 0)) { BN_rshift1(d, d); s++; }

    for (i = 0; i < iterations; i++) {
        BN_sub(tmp, n, bn_two); BN_rand_range(a, tmp);
        if (BN_cmp(a, bn_two) < 0) BN_add(a, a, bn_two);
        BN_mod_exp(x, a, d, n, ctx);
        if (BN_is_one(x) || BN_cmp(x, n_minus1) == 0) continue;
        for (j = 1; j < s; j++) {
            BN_mod_mul(x, x, x, n, ctx);
            if (BN_cmp(x, n_minus1) == 0) break;
            if (BN_is_one(x)) { ret = 0; goto end; }
        }
        if (j < s) continue;
        ret = 0; goto end;
    }
    ret = 1;
end:
    BN_CTX_end(ctx);
    return ret;
}

static int check_strong_prime(const BIGNUM *p) {
    init_constants();
    if (BN_cmp(p, strong_k_bn) <= 0) return 0;
    return (BN_mod_word(p, min_prime_bound_word) == strong_r_plus1);
}

static int my_generate_prime(BIGNUM *prime, int bits, int iterations, BN_CTX *ctx) {
    BN_rand(prime, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    init_constants();
    while (1) {
        if (BN_mod_word(prime, pubexp_word) != 1 && check_strong_prime(prime)) {
            if (my_miller_rabin(prime, iterations, ctx) == 1)
                return 1;
        }
        BN_add_word(prime, 2);
    }
}

static int gen_primes(BIGNUM **p, BIGNUM **q) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    if (!my_generate_prime(*p, KEY_BITS/2, 5, ctx) ||
        !my_generate_prime(*q, KEY_BITS/2, 5, ctx)) {
        BN_CTX_free(ctx); return 0;
    }
    BN_CTX_free(ctx);
    return 1;
}
static int gen_ned(BIGNUM *p, BIGNUM *q, BIGNUM **n, BIGNUM **e, BIGNUM **d)
 {
     BN_CTX *ctx = BN_CTX_new();
     // init scratch BNs
     BIGNUM *s1 = BN_new();
     BIGNUM *s2 = BN_new();
     BIGNUM *s3 = BN_new();
     if(p == NULL || q == NULL || ctx == NULL || s1 == NULL || s2 == NULL || s3 == NULL)
         goto err;
 
     if(BN_mul(*n, p, q, ctx) < 1)
         goto err;
 
     // p-1 and q-1 in s1 and s2
     if(BN_copy(s1, p) == NULL || BN_copy(s2, q) == NULL ||
        BN_sub_word(s1, 1) < 1 || BN_sub_word(s2, 1) < 1)
         goto err;
 
     if(BN_mul(s3, s1, s2, ctx) < 1 || BN_gcd(s2, s1, s2, ctx) < 1 ||
        BN_div(s1, NULL, s3, s2, ctx) < 1)
         goto err;
 
     do {
         BN_rand_ex(*e, KEY_N_ENT, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD, 0, ctx);
         if(BN_mod_inverse(*e, *e, s1, ctx) == NULL)
             continue;
 
         if(BN_cmp(*e, BN_value_one()) != 1 || BN_cmp(*e, s1) != -1 ||
            BN_gcd(s2, s2, *e, ctx) < 1 || !BN_is_one(s2))
             continue;
 
         if(BN_mod_inverse(*d, *e, s1, ctx) != NULL)
             break;
     } while(1);

 
     BN_free(s1);
     BN_free(s2);
     BN_free(s3);
     BN_CTX_free(ctx);
     return 1;
 err:
     if(s1 != NULL) BN_free(s1);
     if(s2 != NULL) BN_free(s2);
     if(s3 != NULL) BN_free(s3);
     if(ctx != NULL) BN_CTX_free(ctx);
     fprintf(stderr, "gen_key failed\n");
     ERR_print_errors_fp(stderr);
     return 0;
 }

static int gen_pkey(EVP_PKEY **pkey, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    OSSL_PARAM_BLD *pb = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params;
    EVP_PKEY_fromdata_init(ctx);
    OSSL_PARAM_BLD_push_BN(pb, "n", n);
    OSSL_PARAM_BLD_push_BN(pb, "e", e);
    OSSL_PARAM_BLD_push_BN(pb, "d", d);
    params = OSSL_PARAM_BLD_to_param(pb);
    EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_KEYPAIR, params);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(pb);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

EVP_PKEY *generate_key(void) {
    BIGNUM *p = BN_new(), *q = BN_new();
    BIGNUM *n = BN_new(), *e = BN_new(), *d = BN_new();
    EVP_PKEY *ret = NULL;
    gen_primes(&p, &q);
    gen_ned(p, q, &n, &e, &d);
    gen_pkey(&ret, n, e, d);

    /* print hex values */
    char *nhex = BN_bn2hex(n);
    char *ehex = BN_bn2hex(e);
    char *dhex = BN_bn2hex(d);
    printf("\n== PUBLIC ==\n");
    printf("n = %s\n", nhex);
    printf("e = %s\n", ehex);
    printf("\n== PRIVATE ==\n");
    printf("p = %s\n", BN_bn2hex(p));
    printf("q = %s\n", BN_bn2hex(q));
    printf("d = %s\n", dhex);
    printf("\n== ENCRYPT - DECRYPT ==");
    OPENSSL_free(nhex); OPENSSL_free(ehex); OPENSSL_free(dhex);

    BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(d);
    return ret;
}

int main(int argc, char **argv) {
    ERR_load_crypto_strings();

    /* plaintext is already set in IN[] = "wpi" */

    EVP_PKEY *pkey = generate_key();
    if (!pkey) return 1;

    /* encrypt */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
    size_t enclen = BUFFER_SIZE;
    if (EVP_PKEY_encrypt(ctx, OUT, &enclen, IN, BUFFER_SIZE) <= 0) {
        printf("\nEncrypt FAIL! - This happens sometimes for math reasons.. just try again :(\n");
        exit(1);
    }

    printf("\nplaintext = %s", IN);
    printf("\ncipher = ");
    for (size_t i = 0; i < enclen; i++) printf("%02x", OUT[i]);
    printf("\n");

    /* decrypt */
    uint8_t DEC[BUFFER_SIZE] = {0};
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING);
    size_t declen = BUFFER_SIZE;
    if (EVP_PKEY_decrypt(ctx, DEC, &declen, OUT, enclen) <= 0) {
        print_error("decrypt");
        return 1;
    }
    printf("decrypt = %.*s\n", (int)declen, DEC);

    EVP_PKEY_free(pkey);
    return 0;
}
