//
// Created by maxxie on 16-5-24.
//

#include <cstdlib>
#include <cstring>
#include "damgard_jurik.h"

damgard_jurik_text_t::damgard_jurik_text_t(mpz_t text) {
    mpz_init(this->text);
    mpz_set(this->text, text);
}

damgard_jurik_text_t::damgard_jurik_text_t() {
    mpz_init(text);
}

damgard_jurik_text_t::damgard_jurik_text_t(unsigned long integer) {
    mpz_init(text);
    mpz_init_set_ui(text, integer);
}

damgard_jurik_text_t::damgard_jurik_text_t(void *bytes, int len) {
    mpz_init(text);
    mpz_import(text, len, 1, 1, 0, 0, bytes);
}

damgard_jurik_text_t::damgard_jurik_text_t(const char str[]) {
    mpz_init(text);
    mpz_import(text, strlen(str), 1, 1, 0, 0, str);
}

char* damgard_jurik_text_t::to_str() {
    char *buf;
    size_t len;
    buf = (char *)mpz_export(NULL, &len, 1, 1, 0, 0, text);
    buf[len] = 0;
    return buf;
}

void* damgard_jurik_text_t::to_bytes() {
    void *buf;
    void *buf_1 = malloc(this->size());
    memset(buf_1, 0, this->size());
    size_t written;
    buf = mpz_export(NULL, &written, 1, 1, 0, 0, text);
    if (written == this->size())
        return buf;
    memcpy((unsigned char *)buf_1 + (this->size() - written), buf, written);
    free(buf);
    return buf_1;
}

void* damgard_jurik_text_t::to_bytes(size_t len) {
    void *buf;
    void *buf_1 = malloc(len);
    memset(buf_1, 0, len);
    size_t written;
    buf = mpz_export(NULL, &written, 1, 1, 0, 0, text);
    if (written == len)
        return buf;
    if (written > len)
        memcpy(buf_1, buf + written - len, len);
    else
        memcpy((unsigned char *)buf_1 + (len - written), buf, written);
    free(buf);
    return buf_1;
}

size_t damgard_jurik_text_t::size() {
    return mpz_size(text) * sizeof(mp_limb_t);
}

damgard_jurik_ciphertext_t operator*(damgard_jurik_ciphertext_t a, damgard_jurik_ciphertext_t b) {
    damgard_jurik_ciphertext_t return_object;
    mpz_init(return_object.text);
    mpz_mul(return_object.text, a.text, b.text);
    mpz_mod(return_object.text, return_object.text, a.n_s);
    mpz_set(return_object.n_s, a.n_s);
    return_object.s = a.s;
    return return_object;
}

damgard_jurik_ciphertext_t operator^(damgard_jurik_ciphertext_t &a, damgard_jurik_text_t &b) {
    damgard_jurik_ciphertext_t return_object;
    mpz_init(return_object.text);
    mpz_powm(return_object.text, a.text, b.text, a.n_s);
    mpz_set(return_object.n_s, a.n_s);
    return_object.s = a.s;
    return return_object;
}

void damgard_jurik::init_rand(gmp_randstate_t rand, int bytes) {
    void* buf;
    mpz_t s;

    buf = new char[bytes];
    this->rand_func(buf, bytes);

    gmp_randinit_default(rand);
    mpz_init(s);
    mpz_import(s, bytes, 1, 1, 0, 0, buf);
    gmp_randseed(rand, s);
    mpz_clear(s);

    free(buf);
}

mpz_t* damgard_jurik::get_ns(int s) {
	return &pubkey->n_j[s];
}

void damgard_jurik_function_l(mpz_t result ,mpz_t b, mpz_t n) {
    mpz_sub_ui(result, b, 1);
    mpz_div(result, result, n);
}

void damgard_jurik::compute_cache() {
    mpz_t tmp;
    mpz_init(tmp);
    pubkey->n_j = new mpz_t[s_max + 2];
    pubkey->k_n = new mpz_t[s_max + 2];
    pubkey->nj_d_j = new mpz_t[s_max + 2];
    pubkey->nj1_d_j = new mpz_t[s_max + 2];
    mpz_init(pubkey->n_j[0]);
    mpz_set_ui(pubkey->n_j[0], 1);
    mpz_init(pubkey->k_n[0]);
    mpz_set_ui(pubkey->k_n[0], 1);
    for (int i = 1;i <= s_max + 1;i++) {
        mpz_init(pubkey->n_j[i]);
        mpz_mul(pubkey->n_j[i], pubkey->n_j[i - 1], pubkey->n);

        mpz_init(pubkey->k_n[i]);
        mpz_mul_ui(pubkey->k_n[i], pubkey->k_n[i - 1], i);
    }

    for (int i = 2;i <= s_max + 1;i++) {
        mpz_init(pubkey->nj1_d_j[i]);
        mpz_invert(tmp, pubkey->k_n[i], pubkey->n_j[s_max + 1]);
        mpz_mul(pubkey->nj1_d_j[i], pubkey->n_j[i - 1], tmp);
        mpz_mod(pubkey->nj1_d_j[i], pubkey->nj1_d_j[i], pubkey->n_j[s_max + 1]);

        mpz_init(pubkey->nj_d_j[i]);
        mpz_mul(pubkey->nj_d_j[i], pubkey->nj1_d_j[i], pubkey->n);
        mpz_mod(pubkey->nj_d_j[i], pubkey->nj_d_j[i], pubkey->n_j[s_max + 1]);
    }
}

void damgard_jurik::compute_exp(mpz_t *result, mpz_t *msg, unsigned long s) {
    mpz_t tmp;
    mpz_t tmp_mid;
    mpz_mul(*result, pubkey->n, *msg);
    mpz_add_ui(*result, *result, 1);
    mpz_init(tmp);
    mpz_init(tmp_mid);
    mpz_set(tmp, *msg);
    for (int i = 2;i <= s;i++) {
        mpz_sub_ui(tmp_mid, *msg, i - 1);
        mpz_mul(tmp, tmp, tmp_mid);
        mpz_mod(tmp, tmp, pubkey->n_j[s - i + 1]);
        mpz_mul(tmp_mid, tmp, pubkey->nj_d_j[i]);
        mpz_mod(tmp_mid, tmp_mid, pubkey->n_j[s + 1]);
        mpz_add(*result, *result, tmp_mid);
        mpz_mod(*result, *result, pubkey->n_j[s + 1]);
    }
}

void damgard_jurik::key_gen(int modulusbits) {
    mpz_t p, q;

    gmp_randstate_t rand;
    mpz_init(pubkey->n);
    mpz_init(pubkey->g);
    mpz_init(prvkey->lambda);
    mpz_init(p);
    mpz_init(q);

    init_rand(rand, modulusbits / 8 + 1);
    do
    {
        do
            mpz_urandomb(p, rand, modulusbits / 2);
        while( !mpz_probab_prime_p(p, 10) );

        do
            mpz_urandomb(q, rand, modulusbits / 2);
        while( !mpz_probab_prime_p(q, 10) );

        /* compute the public modulus n = p q */

        mpz_mul(pubkey->n, p, q);
    } while( !mpz_tstbit(pubkey->n, modulusbits - 1));
    pubkey->bits = modulusbits;

    mpz_add_ui(pubkey->g, pubkey->n, 1);

    compute_cache();

    /* Compute Private Key */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(prvkey->lambda, p, q);

    mpz_clear(p);
    mpz_clear(q);
    gmp_randclear(rand);
}

void* damgard_jurik::export_pubkey(size_t *len) {
    void *buff;
    size_t written;
    buff = mpz_export(NULL, &written, 1, 1, 0, 0, pubkey->n);
    *len = written;
    return buff;
}

void* damgard_jurik::export_prvkey(size_t *len) {
    void *buff;
    size_t written;
    buff = mpz_export(NULL, &written, 1, 1, 0, 0, prvkey->lambda);
    *len = written;
    return buff;
}

damgard_jurik::damgard_jurik(unsigned long s, int bitsmodule, damgard_jurik_get_rand_t rand_func, void *buf, size_t len) {
    mpz_t tmp;
    pubkey = new damgard_jurik_pubkey_t();
    prvkey = NULL;
    this->s_max = s;
    this->rand_func = rand_func;

    mpz_init(pubkey->n);
    mpz_init(pubkey->g);
    mpz_init(tmp);
    mpz_import(pubkey->n, len, 1, 1, 0, 0, buf);

    pubkey->bits = bitsmodule;

    mpz_add_ui(pubkey->g, pubkey->n, 1);
    compute_cache();

}

damgard_jurik::damgard_jurik(unsigned long s, int bitsmodule, damgard_jurik_get_rand_t rand_func,
                                    void *buf, size_t len, void* pvk_buf, size_t pvk_len) {
    mpz_t tmp;
    pubkey = new damgard_jurik_pubkey_t();
    prvkey = new damgard_jurik_prvkey_t();
    this->s_max = s;
    this->rand_func = rand_func;

    mpz_init(pubkey->n);
    mpz_init(pubkey->g);
    mpz_init(tmp);
    mpz_import(pubkey->n, len, 1, 1, 0, 0, buf);

    pubkey->bits = bitsmodule;

    mpz_add_ui(pubkey->g, pubkey->n, 1);
    compute_cache();

    mpz_init(prvkey->lambda);
    mpz_import(prvkey->lambda, pvk_len, 1, 1, 0, 0, pvk_buf);

}

damgard_jurik::damgard_jurik(unsigned long s, int bitsmodule, damgard_jurik_get_rand_t rand_func) {
    pubkey = new damgard_jurik_pubkey_t();
    prvkey = new damgard_jurik_prvkey_t();
    this->s_max = s;
    this->rand_func = rand_func;
    key_gen(bitsmodule);
}

damgard_jurik_ciphertext_t* damgard_jurik::encrypt(damgard_jurik_plaintext_t* pt, unsigned long s) {
    mpz_t r;
    gmp_randstate_t rand;
    mpz_t x;
    mpz_t gc;
    damgard_jurik_ciphertext_t *res = new damgard_jurik_ciphertext_t();
    /* pick random blinding factor */

    mpz_init(r);
    mpz_init(gc);
    init_rand(rand, pubkey->bits / 8 + 1);
    do {
        mpz_urandomb(r, rand, pubkey->bits);
        mpz_gcd(gc, r, pubkey->n);
    }while( mpz_cmp(r, pubkey->n) >= 0 || mpz_cmp_ui(gc, 1) > 0 || mpz_cmp_ui(r, 0) == 0);

    mpz_init(x);
//    mpz_powm(res->text, pubkey->g, pt->text, pubkey->n_j[s + 1]);
    compute_exp(&res->text, &pt->text, s);
    mpz_powm(x, r, pubkey->n_j[s], pubkey->n_j[s + 1]);

    mpz_mul(res->text, res->text, x);
    mpz_mod(res->text, res->text, pubkey->n_j[s + 1]);

    mpz_set(res->n_s, pubkey->n_j[s + 1]);
    res->s = s;
    mpz_clear(x);
    mpz_clear(r);
    gmp_randclear(rand);

    return res;
}

void damgard_jurik::encrypt(damgard_jurik_ciphertext_t **list, damgard_jurik_plaintext_t **text, unsigned long s, int size) {
	mpz_t r;
	gmp_randstate_t rand;
	mpz_t x;
    mpz_t gc;
	/* pick random blinding factor */

	mpz_init(r);
    mpz_init(gc);

	init_rand(rand, pubkey->bits / 8 + 1);
	do {
        mpz_urandomb(r, rand, pubkey->bits);
        mpz_gcd(gc, r, pubkey->n);
    }while (mpz_cmp(r, pubkey->n) >= 0 || mpz_cmp_ui(gc, 1) > 0 || mpz_cmp_ui(r, 0) == 0);

	mpz_init(x);
	mpz_powm(x, r, pubkey->n_j[s], pubkey->n_j[s + 1]);
	for (int i = 0; i < size; i++) {
		list[i] = new damgard_jurik_ciphertext_t();

//		mpz_powm(list[i]->text, pubkey->g, text[i]->text, pubkey->n_j[s + 1]);
        compute_exp(&list[i]->text, &text[i]->text, s);
		mpz_mul(list[i]->text, list[i]->text, x);
		mpz_mod(list[i]->text, list[i]->text, pubkey->n_j[s + 1]);

		mpz_set(list[i]->n_s, pubkey->n_j[s + 1]);
		list[i]->s = s;
	}
	mpz_clear(x);
	mpz_clear(r);
	gmp_randclear(rand);
}

damgard_jurik_ciphertext_t* damgard_jurik::encrypt(damgard_jurik_plaintext_t* pt) {
    return encrypt(pt, get_s(pt));
}

damgard_jurik_plaintext_t* damgard_jurik::decrypt(damgard_jurik_ciphertext_t* ct) {
    damgard_jurik_plaintext_t *res = new damgard_jurik_plaintext_t();
    mpz_t c_r;
    mpz_t l_a;

    mpz_init(c_r);
    mpz_init(l_a);

    mpz_powm(c_r, ct->text, prvkey->lambda, pubkey->n_j[ct->s + 1]);

    int i, j;
    mpz_t t1, t2, t3, i_lamda;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(i_lamda);
    mpz_set_ui(i_lamda, 0);
    damgard_jurik_function_l(l_a, c_r, pubkey->n_j[1]);
    for (i = 1;i <= ct->s;++i) {
        mpz_mod(t1, l_a, pubkey->n_j[i]);
//        damgard_jurik_function_l(t1, t1, pubkey->n_j[1]);
        mpz_set(t2, i_lamda);
        for (j = 2;j <= i;j++) {
            mpz_sub_ui(i_lamda, i_lamda, 1);
            mpz_mul(t2, t2, i_lamda);
            mpz_mod(t2, t2, pubkey->n_j[i]);
            mpz_mod(t3, pubkey->nj1_d_j[j], pubkey->n_j[i]);
            mpz_mul(t3, t3, t2);
            mpz_mod(t3, t3,pubkey->n_j[i]);
            /*
            mpz_set(t3, pubkey->k_n[j]);
            mpz_invert(t3, t3, pubkey->n_j[i]);
            mpz_mul(t3, t2, t3);
            mpz_mod(t3, t3, pubkey->n_j[i]);
            mpz_mul(t3, t3, pubkey->n_j[j - 1]);
            mpz_mod(t3, t3, pubkey->n_j[i]);
            */
            mpz_sub(t1, t1, t3);
            mpz_mod(t1, t1, pubkey->n_j[i]);
        }
        mpz_set(i_lamda, t1);
    }

    mpz_invert(t3, prvkey->lambda, pubkey->n_j[ct->s]);
    mpz_mul(res->text, i_lamda, t3);
    mpz_mod(res->text, res->text, pubkey->n_j[ct->s]);

    return res;
}

unsigned long damgard_jurik::get_s(damgard_jurik_text_t *te) {
    size_t len = te->size();
    return len / pubkey->bits * 8 + 1;
}