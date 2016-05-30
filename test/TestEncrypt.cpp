//
// Created by maxxie on 16-5-23.
//
#include <cassert>
#include "../src/OramCrypto.h"
#include "../src/damgard_jurik.h"

//#include "crypt.hpp"
int main (int argc, char **args) {
/*  //damgard_jurik test
    char buf[1024];
    buf[0] = 1;
    buf[1] = 2;
*/
    damgard_jurik dj = damgard_jurik(50, 1024, randombytes_buf);
    size_t len;
    void *bb = dj.export_pubkey(&len);
    damgard_jurik dj_dum = damgard_jurik(50, 1024, randombytes_buf, bb, len);
    damgard_jurik_plaintext_t text_1 = damgard_jurik_plaintext_t("abc");
    damgard_jurik_plaintext_t text_2 = damgard_jurik_plaintext_t("efg");
    damgard_jurik_ciphertext_t *text_1_c = dj.encrypt(&text_1, 9);
    damgard_jurik_ciphertext_t *text_2_c = dj.encrypt(&text_2, 9);
//    damgard_jurik_plaintext_t text_3 = damgard_jurik_plaintext_t(buf, 1024);
    damgard_jurik_plaintext_t sec_1 = damgard_jurik_plaintext_t((unsigned long)0);
    damgard_jurik_plaintext_t sec_2 = damgard_jurik_plaintext_t((unsigned long)1);
    damgard_jurik_ciphertext_t *c_1 = dj_dum.encrypt(&sec_1, 10);
    damgard_jurik_ciphertext_t *c_22 = dj_dum.encrypt(&sec_2, 10);
//    damgard_jurik_ciphertext_t *c_4 = dj.encrypt(&text_3, 10);
    damgard_jurik_ciphertext_t c_3 = (*c_1^text_1) * (*c_22^text_2);
    damgard_jurik_plaintext_t *se_p = dj.decrypt(&c_3);
    int o = mpz_cmp(dj.get_pubkey()->n, dj_dum.get_pubkey()->n);
    char *aa = (char *)dj.decrypt(&c_3)->to_str();


    char *key = "ORAM";
    unsigned char buf[40960];
    buf[0] = 1;
    buf[1] = 1;
    OramCrypto::init_crypto(key, 4, 33, 50, 1024);
    damgard_jurik_plaintext_t *plaintext = new damgard_jurik_plaintext_t(buf, 2048);
    unsigned char *b = (unsigned char *)plaintext->to_bytes();
    damgard_jurik_ciphertext_t *c = OramCrypto::get_crypto()->ahe_sys->encrypt(plaintext, 33);
    unsigned char *a = (unsigned char *)OramCrypto::get_crypto()->ahe_sys->decrypt(c)->to_bytes();

    //Onion
    damgard_jurik_ciphertext_t *c_on = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t(c->text), 34);
    damgard_jurik_plaintext_t *pl = OramCrypto::get_crypto()->ahe_sys->decrypt(c_on);
    damgard_jurik_plaintext_t *pll = OramCrypto::get_crypto()->ahe_sys->decrypt(new damgard_jurik_ciphertext_t(pl->text, 33));
    unsigned char *f = (unsigned char *)pll->to_bytes();

    //list encryption
    damgard_jurik_ciphertext_t **ci_list = (damgard_jurik_ciphertext_t**)malloc(sizeof(damgard_jurik_ciphertext_t*)*2);
    ci_list[0] = c;

    void *c_bytes = c->to_bytes();
    int chunk_size = OramCrypto::get_crypto()->get_chunk_size(1);
    damgard_jurik_ciphertext_t *c_2 = new damgard_jurik_ciphertext_t(c_bytes, chunk_size);
    int same = mpz_cmp(c_2->text, c->text);

    OramMeta meta;
    meta.size = 10;
    meta.address = new int[10];
    meta.address[0] = 1;
    void *meta_buf = OramCrypto::get_crypto()->encrypt_meta(meta, NULL);
    OramMeta *me = OramCrypto::get_crypto()->decrypt_meta(meta_buf, 10);
    return 0;
}