#ifndef CONSTS_H
#define CONSTS_H

//define consts as floats
#define SQRT2 1.41421356237309504880
#define BYTE_SIZE 8

//block size in bytes, not bits...
#define SMALL_BLOCK 1
#define MEDIUM_BLOCK 16
#define LARGE_BLOCK 32

typedef struct BlockConsts
{
    unsigned int size;
    unsigned int K;
    unsigned int N;
    unsigned int V[6];
    float pi[6];
} BlockConsts; 

static const BlockConsts small_block_consts =  {4, 3, 16, {1, 2, 3, 4}, 
                                            {0.2148, 0.3672, 0.2305, 0.1875}};
static const BlockConsts medium_block_consts = {6, 5, 49, {4, 5, 6, 7, 8, 9}, 
                                            {0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124}};
static const BlockConsts large_block_consts =  {6, 5, 49, {6, 7, 8, 9, 10, 11}, 
                                            {0.1170, 0.2460, 0.2523, 0.1755, 0.1027, 0.1124}};

#endif
