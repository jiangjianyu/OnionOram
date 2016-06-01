//
// Created by maxxie on 16-5-28.
//
#include <cassert>
#include "../src/OramSelector.h"
#include "../src/OramCrypto.h"

int main(int argc, char **args) {
    char *key = "ORAM";

    OramCrypto::init_crypto(key, 4, 9, 100, 1024);
    OramBlock::init_size(1024, 10240);

    unsigned char buf[40960];
    OramBlock **block_list = (OramBlock**)malloc(sizeof(OramBlock*)*5);
    for (int i = 0;i<1;i++) {
        buf[0] = 0;
        block_list[0] = new OramBlock(buf);
        unsigned char *de_0 = (unsigned char*)block_list[0]->decrypt();
        buf[0] = 1;
        block_list[1] = new OramBlock(buf);
        unsigned char *de_1 = (unsigned char*)block_list[1]->decrypt();
        buf[0] = 2;
        block_list[2] = new OramBlock(buf);
        unsigned char *de_2 = (unsigned char*)block_list[2]->decrypt();
        buf[0] = 3;
        block_list[3] = new OramBlock(buf);
        unsigned char *de_3 = (unsigned char*)block_list[3]->decrypt();
        buf[0] = 4;
        block_list[4] = new OramBlock(buf);
        unsigned char *de_4 = (unsigned char*)block_list[4]->decrypt();

        OramSelector *oramSelector = new OramSelector(5, 1, 1);
//
//        damgard_jurik_ciphertext_t *sec_0 = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t((unsigned long)0), 10);
//        damgard_jurik_ciphertext_t *sec_1 = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t((unsigned long)0), 10);
//        damgard_jurik_ciphertext_t sec_result = ((*sec_0)^(*block_list[1]->block[0])) * ((*sec_1)^(*block_list[2]->block[0])) ;
//        damgard_jurik_plaintext_t *pl = OramCrypto::get_crypto()->ahe_sys->decrypt(&sec_result);
//        unsigned char * one_de = (unsigned char *)pl->to_bytes();
//        damgard_jurik_ciphertext_t *dd = new damgard_jurik_ciphertext_t(pl->text, 9);
//        damgard_jurik *dj = OramCrypto::get_crypto()->get_crypto()->ahe_sys;
//        unsigned char *ded = (unsigned char *)OramCrypto::get_crypto()->ahe_sys->decrypt(dd)->to_bytes();
        OramBlock *select_block = oramSelector->select(block_list);
        unsigned char *de_blo = (unsigned char *) select_block->decrypt();
        assert(de_blo[0] == i % 5 + 1);

        void *by = oramSelector->to_bytes();
        OramSelector *oramSelector_re = new OramSelector(5, by, 1);
        for (int j = 0;j < 5;j++) {
            assert(mpz_cmp(oramSelector->select_vector[j]->text, oramSelector_re->select_vector[j]->text) == 0);
        }

    }
    return 0;

}