#include "utils.h"
#include <stdio.h>
/* calulate the ratio of 1 and 0 bits. If there are
 * an even amount of bits, return 0. Positive means
 * that there are more ones than zeros. Negative means
 * that there are more zeros than ones. */
int bit_sum(unsigned char* buf, unsigned int buf_len)
{
    unsigned int sum = 0;
    unsigned int i;
    int ratio[16] = {-4, -2, -2,  0, 
                     -2,  0,  0,  2, 
                     -2,  0,  0,  2,
                      0,  2,  2,  4};
    for(i = 0; i < buf_len; i++)
      sum += ratio[buf[i] & 0x0f] + ratio[buf[i] >> 4];
  
    return sum;
}

/*count the number of 1 bits in a single byte*/
unsigned int bit_count(unsigned char byte)
{
    const unsigned int lookup[16] = {0, 1, 1, 2, 1, 2, 2, 3,
                                     1, 2, 2, 3, 2, 3, 3, 4};
    return lookup[0x0f & byte] + lookup[byte >> 4];
}

/*counts the numbers of 1 bits in a buffer*/
unsigned int ones_count(unsigned char* buf, unsigned int buf_len)
{
    unsigned int sum = 0;
    for(unsigned int i = 0; i < buf_len; i++)
        sum += bit_count(buf[i]);
    return sum;
}

/*count the number of times a run of bits switches from
 * a zero to a one or vice versa */
unsigned int run_count(unsigned char* buf, unsigned int buf_len)
{   
    unsigned int run_sum = 0;
    unsigned int previous;
    int check_boundry = 0;
    for(unsigned int i = 0; i < buf_len; i++)
    {
        if(check_boundry > 0)
            run_sum += (buf[i] & 0x01) ^ previous; 
        for(unsigned int j = 1; j < BYTE_SIZE; j++)
            run_sum += ((buf[i] >> j) & 0x01) ^ ((buf[i] >> (j-1)) & 0x01);
         previous = (buf[i] >> (BYTE_SIZE - 1)) & 0x01;
         check_boundry = 1;
    }
    return run_sum + 1;
}

unsigned int longest_one_run(unsigned char* buf, unsigned int buf_size)
{
    unsigned int longest = 0;   //longest runs of 1s so far
    unsigned int current = 0;   //current run of 1s

    for(unsigned int i = 0; i < buf_size; i++)
        for(unsigned int j = 0; j < BYTE_SIZE; j++)
        {
            // check LSB
            if((buf[i] >> j) & 0x01)
                current++;
            else
                current = 0;
                  
            if(current > longest)
                longest = current;
        }
    return longest;
}

/* given a longest run, return the bucket it falls under */ 
unsigned int get_v_bucket(unsigned int ones_run, const BlockConsts* block_consts)
{
    if(ones_run <= block_consts->V[0])
        return 0;
    for(unsigned int i = 1; i < block_consts->K; i++)
        if(ones_run == block_consts->V[i])
            return i;
    return block_consts->K;
}
