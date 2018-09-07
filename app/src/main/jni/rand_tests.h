#ifndef RANDTEST_H
#define RANDTEST_H
/*
 * char* bits holds the data and buf_size is
 * the size of the buffer. The number of bits
 * must be calculated within the function.
 */
float freq_monobit(unsigned char* buf, unsigned int buf_size);
float freq_block(unsigned char* buf, unsigned int buf_size, unsigned int block_size);
float runs(unsigned char* buf, unsigned int buf_size);
float runs_one_block(unsigned char* buf, unsigned int buf_size, unsigned int block_size);

#endif
