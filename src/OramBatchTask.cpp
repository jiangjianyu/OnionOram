//
// Created by maxxie on 16-6-1.
//

#include "OramBatchTask.h"
#include "OramCrypto.h"

OramJob::OramJob(OramJobType type, void *input, OramBatchTask *batch) {
    this->type = type;
    this->input = input;
    this->task = batch;
}

pthread_t* OramBatchTask::thread_list;
int OramBatchTask::job_available;
int OramBatchTask::working = 0;
std::list<OramJob*> OramBatchTask::job_queue;
pthread_mutex_t OramBatchTask::task_mutex;
pthread_cond_t OramBatchTask::task_cond;

void OramBatchTask::init(int worker) {
    thread_list = new pthread_t[worker];
    pthread_mutex_init(&task_mutex, NULL);
    pthread_cond_init(&task_cond, NULL);
    working = 1;
    for (int i = 0;i < worker;i++) {
        pthread_create(&thread_list[i], NULL, work_func, NULL);
    }
}

OramBatchTask* OramBatchTask::new_task() {
    return new OramBatchTask();
}

OramBatchTask::OramBatchTask() {
    pthread_mutex_init(&job_mutex, NULL);
    pthread_cond_init(&job_cond, NULL);
    job_total = 0;
    job_finish = 0;
    all_finish = false;
}

int OramBatchTask::add_job(OramJob *job) {
    pthread_mutex_lock(&job_mutex);
    job_list.push_back(job);
    job_total++;
    pthread_mutex_unlock(&job_mutex);

    pthread_mutex_lock(&task_mutex);
    job_queue.push_back(job);
    job_available++;
    pthread_mutex_unlock(&task_mutex);
    pthread_cond_signal(&task_cond);

    return 1;
}

void * OramBatchTask::work_func(void *args) {
    OramJob *job;
    while(working) {
        pthread_mutex_lock(&task_mutex);
        while (job_available <= 0)
            pthread_cond_wait(&task_cond, &task_mutex);
        job = job_queue.front();
        job_queue.pop_front();
        job_available--;
        pthread_mutex_unlock(&task_mutex);

        damgard_jurik_ciphertext_t *select_result = new damgard_jurik_ciphertext_t();
        //Process task
        if (job->type == ORAM_TASK_DECRYPT) {
            job->result = OramCrypto::get_crypto()->ahe_sys->decrypt((damgard_jurik_ciphertext_t*)job->input);
        } else if (job->type == ORAM_TASK_SELECT) {
            OramTaskSelectInput *input = (OramTaskSelectInput*)job->input;
            *select_result = (*input->select_vector[0]) ^ (*input->select_list[0]->block[input->i]);
            for (int j = 1;j < input->size;j++) {
                *select_result = *select_result *
                ((*input->select_vector[j]) ^ (*input->select_list[j]->block[input->i]));
            }
            job->result = select_result;
        } else if (job->type == ORAM_TASK_ENCRYPT) {
            OramTaskEncryptInput *input = (OramTaskEncryptInput*)job->input;
            job->result = OramCrypto::get_crypto()->ahe_sys->encrypt(input->plaintext, input->s);
        } else if (job->type == ORAM_TASK_NEWBLOCK) {
            job->result = new OramBlock();
        }
        pthread_mutex_lock(&job->task->job_mutex);
        job->task->job_finish++;
        pthread_mutex_unlock(&job->task->job_mutex);
        pthread_cond_signal(&job->task->job_cond);
    }
    return NULL;
}

void* OramBatchTask::get_result(int id) {
    if (!all_finish) {
        pthread_mutex_lock(&job_mutex);
        while (job_finish < job_total)
            pthread_cond_wait(&job_cond, &job_mutex);
        pthread_mutex_unlock(&job_mutex);
        all_finish = true;
    }
    return job_list[id]->result;
}

OramJob* OramBatchTask::new_job(OramJobType type, void *input){
    OramJob *job = new OramJob(type, input, this);
    this->add_job(job);
    return job;
}