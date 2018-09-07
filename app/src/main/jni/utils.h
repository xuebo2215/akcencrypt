#ifndef UTILS_H
#define UTILS_H
#include "consts.h"
int bit_sum(unsigned char* buf, unsigned int buf_len);
unsigned int ones_count(unsigned char* buf, unsigned int buf_len);
unsigned int bit_count(unsigned char byte);
unsigned int run_count(unsigned char* buf, unsigned int buf_len);
unsigned int longest_one_run(unsigned char* buf, unsigned int buf_size);
unsigned int get_v_bucket(unsigned int ones_run, const BlockConsts* block_consts);
#endif
