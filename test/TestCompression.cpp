//
// Created by maxxie on 16-5-31.
//

#include <sodium/randombytes.h>
#include "../src/damgard_jurik.h"

int main(int argc, char **args) {
    mpz_t n_;
    mpz_t n_sp;
    mpz_t n_i;
    mpz_t s_s_1;

    int s = 1;
    unsigned char buf[10240];
    buf[0] = 1;
    damgard_jurik *dj = new damgard_jurik(50, 1024, randombytes_buf);
    damgard_jurik_plaintext_t *te_1 = new damgard_jurik_plaintext_t(buf, 2);
    damgard_jurik_plaintext_t *te_2 = new damgard_jurik_plaintext_t(buf, 2);
    damgard_jurik_ciphertext_t *c_1 = dj->encrypt(new damgard_jurik_plaintext_t((unsigned long)1), 1);
    damgard_jurik_ciphertext_t *c_2 = dj->encrypt(new damgard_jurik_plaintext_t((unsigned long)0), 1);
    mpz_powm(c_1->text, c_1->text, dj->get_pubkey()->n, *dj->get_ns(3));
    mpz_powm(c_2->text, c_2->text, dj->get_pubkey()->n, *dj->get_ns(3));
    damgard_jurik_ciphertext_t se = (*c_1^*te_1) * (*c_2^*te_2);
    damgard_jurik_plaintext_t *de = dj->decrypt(&se);
    mpz_add(de->text, de->text, *dj->get_ns(2));
    mpz_div(de->text, de->text, dj->get_pubkey()->n);
    mpz_mod(de->text, de->text, *dj->get_ns(2));
    unsigned char *buff = (unsigned char *)de->to_bytes();
//    damgard_jurik_ciphertext_t *ct_1 = dj->encrypt(new damgard_jurik_plaintext_t("abc"), s);
//    damgard_jurik_ciphertext_t *ct_2 = dj->encrypt(new damgard_jurik_plaintext_t("abc"), s);
//    mpz_init(n_minus);
//    mpz_init(n_sp);
//    mpz_init(n_i);
//    mpz_init(s_s_1);
//    mpz_pow_ui(n_minus, dj->get_pubkey()->n, s);
//    mpz_pow_ui(s_s_1, dj->get_pubkey()->n, s + 1);
//    mpz_pow_ui(n_sp, dj->get_pubkey()->n, s + 2);
//    mpz_powm(c_1->text, c_1->text, n_minus, n_sp);
//    mpz_powm(c_2->text, c_2->text, n_minus, n_sp);
//    mpz_set(c_1->n_s, n_sp);
//    mpz_set(c_2->n_s, n_sp);
//    damgard_jurik_ciphertext_t se = (*c_1^*ct_1) * (*c_2^*ct_2);
//    damgard_jurik_plaintext_t *se_de = dj->decrypt(&se);
//    mpz_invert(n_i, n_minus, s_s_1);
//    mpz_mul(se_de->text, se_de->text, n_i);
//    mpz_mod(se_de->text, se_de->text,s_s_1);
//    unsigned char *bu = (unsigned char *)dj->decrypt(new damgard_jurik_ciphertext_t(se_de->text, s))->to_str();
    return 0;
}