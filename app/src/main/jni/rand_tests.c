#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "rand_tests.h"
#include "consts.h"
#include "utils.h"
#include "cephes.h"

float freq_monobit(unsigned char* buf, unsigned int buf_size)
{
    int sum = bit_sum(buf, buf_size);
    float s_obs = fabs(sum)/sqrt(buf_size * BYTE_SIZE);
    return erfc(s_obs/SQRT2);
}

float freq_block(unsigned char* buf, unsigned int buf_size, unsigned int block_size)
{
    int block_sum;
    float sum = 0.0;
    unsigned int num_blocks = buf_size / block_size;
    float pi, chi_sq;
    for(unsigned int i = 0; i < num_blocks; i++)
    {
        block_sum = ones_count(&buf[i*block_size], block_size);
        pi = ((float) block_sum / ((float)block_size * BYTE_SIZE)) - 0.5;
        sum += pi*pi;
    }
    chi_sq = 4.0 * (float) block_size * BYTE_SIZE * sum;
    printf("qs=%f, psum=%f\n", chi_sq, cephes_igamc(num_blocks/2.0, chi_sq/2.0));
    return cephes_igamc(num_blocks/2.0, chi_sq/2.0);
}


float runs(unsigned char* buf, unsigned int buf_size)
{
    //pre-test
    float pi = ((float) ones_count(buf, buf_size)) / ((float) buf_size * BYTE_SIZE);
    unsigned int run_sum;
    if(fabs(pi - 0.5) > (2.0 / sqrt(buf_size * BYTE_SIZE)))
        return 0.0;
    else
        run_sum = run_count(buf, buf_size);
    float out = erfc(fabs(run_sum - 2 * buf_size * BYTE_SIZE * pi *(1-pi)) 
                / (2*pi*(1-pi)*sqrt(2*buf_size * BYTE_SIZE)));
    //printf("p=%f\n", out);
    return out;
}

float runs_one_block(unsigned char* buf, unsigned int buf_size, unsigned int block_size)
{
    const BlockConsts* block_consts;
    unsigned int longest_run_in_block;
    unsigned int* v_count;
    float chi_sq = 0.0;
    unsigned int num_blocks = buf_size / block_size;

    //check if the block size is supported
    if(block_size == SMALL_BLOCK && small_block_consts.N <= num_blocks){
        block_consts = &small_block_consts;
    }
    else if(block_size == MEDIUM_BLOCK && medium_block_consts.N <= num_blocks){
        block_consts = &medium_block_consts;
    }
    else
    {
        printf("Invalid block size in `runs_one_block' OR LARGE_BLOCK not supported!\n");
        return -1.0;
    }
    
    v_count = (unsigned int *) calloc(block_consts->size, sizeof(unsigned int));
    for(unsigned int i = 0; i < num_blocks; i++)
    {
        longest_run_in_block = longest_one_run(&buf[i*block_size], block_size);
        v_count[ get_v_bucket(longest_run_in_block, block_consts) ] += 1;
    } 
    
    for(unsigned int i = 0; i < block_consts->size; i++)
        chi_sq += pow(v_count[i] - num_blocks*block_consts->pi[i],2)/(num_blocks * block_consts->pi[i]);

    float out = cephes_igamc(block_consts->K/2.0, chi_sq/2.0);
    //printf("pval: %f\n", out);
    free(v_count);
    return out;
}
