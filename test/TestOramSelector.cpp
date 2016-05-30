//
// Created by maxxie on 16-5-28.
//
#include <cassert>
#include "../src/OramSelector.h"
#include "../src/OramCrypto.h"

int main(int argc, char **args) {
    char *key = "ORAM";

    OramCrypto::init_crypto(key, 4, 8, 100, 1024);
    OramBlock::init_size(1024, 10240);

    unsigned char buf[40960];
    OramBlock **block_list = (OramBlock**)malloc(sizeof(OramBlock*)*5);
    for (int i = 0;i<1;i++) {
        buf[0] = 1;
        block_list[0] = new OramBlock(buf);
        buf[0] = 2;
        block_list[1] = new OramBlock(buf);
        buf[0] = 3;
        block_list[2] = new OramBlock(buf);
        buf[0] = 4;
        block_list[3] = new OramBlock(buf);
        buf[0] = 5;
        block_list[4] = new OramBlock(buf);

        OramSelector *oramSelector = new OramSelector(5, -1, 1);

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