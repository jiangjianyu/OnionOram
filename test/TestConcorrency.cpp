//
// Created by maxxie on 16-6-1.
//

#include "../src/OramBatchTask.h"
#include "../src/OramCrypto.h"

int main(int argc, char **args) {
    char *key = "ORAM";
    OramCrypto::init_crypto(key, 4, 9, 100, 1024);
    damgard_jurik_ciphertext_t *c1 = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t("abc"));
    damgard_jurik_ciphertext_t *c2 = OramCrypto::get_crypto()->ahe_sys->encrypt(new damgard_jurik_plaintext_t("abc"));
    unsigned char buf[20240];
    OramBatchTask::init(4);
    OramBatchTask *task = OramBatchTask::new_task();
    task->new_job(ORAM_TASK_DECRYPT, (void *)c1);
    task->new_job(ORAM_TASK_DECRYPT, (void *)c2);
    damgard_jurik_plaintext_t *pt1 = (damgard_jurik_plaintext_t*)task->get_result(0);
    damgard_jurik_plaintext_t *pt2 = (damgard_jurik_plaintext_t*)task->get_result(1);
    unsigned char *by = (unsigned char *)pt1->to_str();
    return 0;

}