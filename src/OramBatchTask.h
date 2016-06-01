//
// Created by maxxie on 16-6-1.
//

#ifndef ONIONORAM_ORAMBATCHTASK_H
#define ONIONORAM_ORAMBATCHTASK_H

#include <list>
#include <pthread.h>
#include <vector>
#include "damgard_jurik.h"
#include "OramBlock.h"

typedef enum OramTaskType {
    ORAM_TASK_ENCRYPT,
    ORAM_TASK_DECRYPT,
    ORAM_TASK_SELECT,
    ORAM_TASK_NEWBLOCK
} OramJobType;

class OramTaskSelectInput {
public:
    int size;
    int i;
    damgard_jurik_ciphertext_t **select_vector;
    OramBlock **select_list;
    OramTaskSelectInput(int si, int ii, damgard_jurik_ciphertext_t **c, OramBlock **se):
            size(si), i(ii), select_vector(c), select_list(se) {}
};

class OramTaskEncryptInput {
public:
    int s;
    damgard_jurik_plaintext_t *plaintext;
    OramTaskEncryptInput(damgard_jurik_plaintext_t *p, int ss):plaintext(p), s(ss){}
};

class OramBatchTask;

class OramJob {
public:
    OramTaskType type;
    void *input;
    void *result;
    OramBatchTask *task;
    OramJob(OramJobType type, void *input, OramBatchTask *batch);
};

class OramBatchTask {
private:
    static pthread_t *thread_list;
    static std::list<OramJob*> job_queue;
    static pthread_mutex_t task_mutex;
    static pthread_cond_t task_cond;
    static int job_available;
    static int working;

    std::vector<OramJob*> job_list;
    int job_total;
    bool all_finish;

public:
    pthread_mutex_t job_mutex;
    pthread_cond_t job_cond;
    int job_finish;

    static void * work_func(void *args);
    static OramBatchTask* new_task();
    static void init(int worker);


    void* get_result(int id);
    int add_job(OramJob *job);
    OramJob *new_job(OramJobType type, void *input);
    OramBatchTask();
};


#endif //ONIONORAM_ORAMBATCHTASK_H
