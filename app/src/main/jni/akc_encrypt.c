//
//  akc_encrypt.c
//  安司密信
//
//  Created by 薛波 on 2017/10/19.
//  Copyright © 2017年 Aegis Inc. All rights reserved.
//

#include "akc_encrypt.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "consts.h"
#include "rand_tests.h"
#include "SFMT.h"


static int byte_cmp(unsigned char *p_left, unsigned char *p_right, int len)
{
    int i;
    for(i = len-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

static int byte_add(unsigned char *p,int len)
{
    int sum=0;
    int i;
    for(i = len-1; i >= 0; --i)
    {
        sum+=p[i];
    }
    return sum;
}

void printBytes(unsigned char* title, unsigned char* bytes, int len)
{
    printf("\n========== %s ==========\n",title);
    unsigned i;
    for(i=0; i<len; i++)
    {
        printf("0x%02x ", (unsigned)bytes[i]);
        if (i!=len-1) {
            printf(",");
        }
    }
    printf("\n====================\n");
}



int sm3ABCTEST()
{
    int res = -1;

    const unsigned char sm3_1[32] = {0x62, 0x34, 0x76 ,0xac ,0x18 ,0xf6 ,0x5a ,0x29 ,0x09 ,0xe4 ,0x3c ,0x7f ,0xec ,0x61 ,0xb4 ,0x9c ,0x7e ,0x76 ,0x4a ,0x91 ,0xa1 ,0x8c ,0xcb ,0x82 ,0xf1 ,0x91 ,0x7a ,0x29 ,0xc8 ,0x6c ,0x5e ,0x88};
    
    const unsigned char sm3_2[32] = {0xaf ,0xe4 ,0xcc ,0xac ,0x5a ,0xb7 ,0xd5 ,0x2b ,0xca ,0xe3 ,0x63 ,0x73 ,0x67 ,0x62 ,0x15 ,0x36 ,0x8b ,0xaf ,0x52 ,0xd3 ,0x90 ,0x5e ,0x1f ,0xec ,0xbe ,0x36 ,0x9c ,0xc1 ,0x20 ,0xe9 ,0x76 ,0x28};
    
    const unsigned char sm3_3[32] = {0x45 ,0x45 ,0x72 ,0xe3 ,0xd1 ,0x52 ,0xbb ,0x8c ,0x3e ,0xf9 ,0x88 ,0x1c ,0xd3 ,0x8d ,0x95 ,0x1d ,0x59 ,0x4c ,0xdc ,0xc3 ,0xe3 ,0xb0 ,0x82 ,0x72 ,0x99 ,0x65 ,0x61 ,0x17 ,0x65 ,0xc9 ,0xd9 ,0xb5};
    
    const unsigned char sm3_4[32] = {0x97 ,0x95 ,0x13 ,0xfd ,0x5e ,0x35 ,0xc3 ,0x81 ,0x8c ,0x2b ,0x21 ,0xc2 ,0x75 ,0x6b ,0xcf ,0x03 ,0x7b ,0xca ,0x34 ,0x15 ,0xe9 ,0x8c ,0x5d ,0xdb ,0xf2 ,0x8d ,0x2a ,0x4e ,0x1b ,0x99 ,0x5c ,0x6f};

    for (int i = 0; i<4; i++) {
        unsigned char test[AKC_KEY_LEN] = {0};
        if (i==0) {
            sm3((unsigned char*)"a",1, test);
        }
        else if (i==1){
            sm3((unsigned char*)"abcde",5, test);
        }
        else if (i==2){
            sm3((unsigned char*)"abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdef",61, test);
        }
        else if (i==3){
            sm3((unsigned char*)"abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabc",128, test);
        }
        unsigned char *testsm3 = malloc(32);
        memcpy(testsm3, test , AKC_KEY_LEN);
        if (i==0) {
            res = byte_cmp(testsm3, (unsigned char*)sm3_1, 32);
        }
        else if (i==1){
            res = byte_cmp(testsm3, (unsigned char*)sm3_2, 32);
        }
        else if (i==2){
            res = byte_cmp(testsm3, (unsigned char*)sm3_3, 32);
        }
        else if (i==3){
            res = byte_cmp(testsm3, (unsigned char*)sm3_4, 32);
        }
        memset(test, 0, AKC_KEY_LEN);
        free(testsm3);
        
        if (res!=0) {
            printf("\n sm3ABCTEST FAIL");
            break;
        }
    }
    return res;
}

int sm4_ENCRYPT_TEST()
{
    int res = 0;
    const unsigned char sm4[16] = {0xbe ,0x70, 0x7f, 0x3b, 0x05, 0xa9, 0xcc, 0x84, 0xad, 0xaf, 0x75, 0xb3, 0x07, 0x45, 0x8e, 0x7c };
    unsigned char *output = 0;
    const unsigned char key[16] = {0x95, 0x8E, 0x72, 0xE6, 0x3C, 0x1B, 0x65, 0xD3, 0x25, 0xAC, 0xF7, 0xF6, 0x50, 0xAF, 0xBA, 0x75};
    const unsigned char iv[16] = {0x32, 0x5E, 0x22, 0x47, 0x58, 0xB0, 0x7C, 0x10, 0x66, 0xBB, 0xC1, 0x5A, 0xC5, 0x46, 0x89, 0xED};
    
    akc_sm4_encrypt((unsigned char*)"ENCRYPTTEST", 11, key, iv, &output);
    
    if (byte_cmp(output, (unsigned char*)sm4, 16)!=0) {
        printf("\n sm4_ENCRYPT_TEST FAIL");
        res =  -1;
    }
    if (output) free(output);
    return res;
}



int sm2signature_TEST()
{
    const unsigned char data[8] = {0x47, 0xd8, 0x3a, 0x47, 0x3d, 0x04, 0xf9, 0xa9};
    unsigned char *signature_out;
    akc_signature(data, 8, &signature_out);
    int signatureVerfyRes = akc_verify_signature(data, 8, signature_out);
    if (signatureVerfyRes!=1) {
        printf("\n akc_signature test fail \n");
        return -1;
    }
    /*
     ========== public_key ==========
     0x54 ,0xad ,0xaf ,0x16 ,0x19 ,0x86 ,0xeb ,0x9f ,0x2b ,0xf0 ,0x26 ,0xac ,0xba ,0x30 ,0xc6 ,0x1d ,0x39 ,0xf2 ,0x08 ,0x88 ,0xee ,0x43 ,0xad ,0x9c ,0xab ,0x91 ,0x99 ,0x6f ,0x61 ,0x70 ,0x74 ,0xd2 ,0x54 ,0xbe ,0xa1 ,0xa3 ,0xf5 ,0x48 ,0x6b ,0x39 ,0x45 ,0x21 ,0x49 ,0x5d ,0xbe ,0x4e ,0x81 ,0x7c ,0x9e ,0x2c ,0x5a ,0x51 ,0xc8 ,0x6b ,0xa1 ,0x61 ,0x79 ,0xc2 ,0x68 ,0x3b ,0xb0 ,0x1e ,0x89 ,0xa9
     ====================
     
     ========== private_key ==========
     0x7d ,0xb9 ,0x98 ,0x97 ,0x97 ,0x20 ,0x08 ,0x37 ,0xfd ,0xac ,0xf0 ,0xd6 ,0xfb ,0xeb ,0x27 ,0xa3 ,0xb0 ,0x2d ,0xc5 ,0x40 ,0x80 ,0x25 ,0xf0 ,0x9b ,0x32 ,0x25 ,0xb2 ,0xda ,0x86 ,0x4c ,0x98 ,0xf9
     ====================
     
     ========== signature_out ==========
     0x1e ,0x4f ,0x2e ,0xe0 ,0x00 ,0x2c ,0x89 ,0x35 ,0x69 ,0xd7 ,0x47 ,0x1c ,0xe7 ,0xf7 ,0xf0 ,0xe5 ,0x53 ,0xb7 ,0xa4 ,0x5b ,0xf0 ,0xe1 ,0x58 ,0x57 ,0x07 ,0xf0 ,0x70 ,0xaf ,0x11 ,0xf5 ,0x22 ,0x38 ,0x90 ,0xe7 ,0xa8 ,0x29 ,0xe9 ,0xce ,0x31 ,0x64 ,0xef ,0xb5 ,0x6b ,0x0b ,0x59 ,0xdf ,0xe5 ,0x22 ,0xfd ,0x4d ,0xa7 ,0x2c ,0x26 ,0x9e ,0x33 ,0xbe ,0x50 ,0xde ,0xe2 ,0xe1 ,0x57 ,0xa0 ,0x9d ,0xde ,0x54 ,0xad ,0xaf ,0x16 ,0x19 ,0x86 ,0xeb ,0x9f ,0x2b ,0xf0 ,0x26 ,0xac ,0xba ,0x30 ,0xc6 ,0x1d ,0x39 ,0xf2 ,0x08 ,0x88 ,0xee ,0x43 ,0xad ,0x9c ,0xab ,0x91 ,0x99 ,0x6f ,0x61 ,0x70 ,0x74 ,0xd2 ,0x54 ,0xbe ,0xa1 ,0xa3 ,0xf5 ,0x48 ,0x6b ,0x39 ,0x45 ,0x21 ,0x49 ,0x5d ,0xbe ,0x4e ,0x81 ,0x7c ,0x9e ,0x2c ,0x5a ,0x51 ,0xc8 ,0x6b ,0xa1 ,0x61 ,0x79 ,0xc2 ,0x68 ,0x3b ,0xb0 ,0x1e ,0x89 ,0xa9
     ====================

     */
    
    /*
     0x1e ,0x4f ,0x2e ,0xe0 ,0x00 ,0x2c ,0x89 ,0x35 ,
     0x69 ,0xd7 ,0x47 ,0x1c ,0xe7 ,0xf7 ,0xf0 ,0xe5 ,
     0x53 ,0xb7 ,0xa4 ,0x5b ,0xf0 ,0xe1 ,0x58 ,0x57 ,
     0x07 ,0xf0 ,0x70 ,0xaf ,0x11 ,0xf5 ,0x22 ,0x38 ,
     0x90 ,0xe7 ,0xa8 ,0x29 ,0xe9 ,0xce ,0x31 ,0x64 ,
     0xef ,0xb5 ,0x6b ,0x0b ,0x59 ,0xdf ,0xe5 ,0x22 ,
     0xfd ,0x4d ,0xa7 ,0x2c ,0x26 ,0x9e ,0x33 ,0xbe ,
     0x50 ,0xde ,0xe2 ,0xe1 ,0x57 ,0xa0 ,0x9d ,0xde ,
     */
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)data,8, id_hash);
    
    unsigned char r[AKC_KEY_LEN] = {0x1e ,0x4f ,0x2e ,0xe0 ,0x00 ,0x2c ,0x89 ,0x35 ,
        0x69 ,0xd7 ,0x47 ,0x1c ,0xe7 ,0xf7 ,0xf0 ,0xe5 ,
        0x53 ,0xb7 ,0xa4 ,0x5b ,0xf0 ,0xe1 ,0x58 ,0x57 ,
        0x07 ,0xf0 ,0x70 ,0xaf ,0x11 ,0xf5 ,0x22 ,0x38};
    unsigned char s[AKC_KEY_LEN] = {0x90 ,0xe7 ,0xa8 ,0x29 ,0xe9 ,0xce ,0x31 ,0x64 ,
        0xef ,0xb5 ,0x6b ,0x0b ,0x59 ,0xdf ,0xe5 ,0x22 ,
        0xfd ,0x4d ,0xa7 ,0x2c ,0x26 ,0x9e ,0x33 ,0xbe ,
        0x50 ,0xde ,0xe2 ,0xe1 ,0x57 ,0xa0 ,0x9d ,0xde};
    unsigned char public_key[AKC_PUBLIC_KEY_LEN] = {0x54 ,0xad ,0xaf ,0x16 ,0x19 ,0x86 ,0xeb ,0x9f ,0x2b ,0xf0 ,0x26 ,0xac ,0xba ,0x30 ,0xc6 ,0x1d ,0x39 ,0xf2 ,0x08 ,0x88 ,0xee ,0x43 ,0xad ,0x9c ,0xab ,0x91 ,0x99 ,0x6f ,0x61 ,0x70 ,0x74 ,0xd2 ,0x54 ,0xbe ,0xa1 ,0xa3 ,0xf5 ,0x48 ,0x6b ,0x39 ,0x45 ,0x21 ,0x49 ,0x5d ,0xbe ,0x4e ,0x81 ,0x7c ,0x9e ,0x2c ,0x5a ,0x51 ,0xc8 ,0x6b ,0xa1 ,0x61 ,0x79 ,0xc2 ,0x68 ,0x3b ,0xb0 ,0x1e ,0x89 ,0xa9};
    
    EccPoint p_publicKey;
    //切割public_key，前32位public.x，后32位public.y，给p_publicKey赋值
    memcpy(p_publicKey.x, (unsigned char *)public_key, AKC_KEY_LEN);
    memcpy(p_publicKey.y, (unsigned char *)public_key+AKC_KEY_LEN, AKC_KEY_LEN);
    
    int verifyres =  ecdsa_verify(&p_publicKey, id_hash, r, s);
    if (verifyres!=1) {
        printf("\n ecdsa_verify test fail \n");
        return -2;
    }
    return 0;
}

int sm2ECDH_TEST()
{
    unsigned char public_key1[64] = {
        0x21 ,0x8e,0x5a ,0x72 ,0xbb ,0x5a ,0x7b ,0x0e ,
        0x67 ,0x3b ,0x7f ,0x94 ,0x05 ,0xe9 ,0x49 ,0x76 ,
        0x40 ,0x2c ,0x08 ,0x03 ,0x61 ,0x14 ,0xa5 ,0x85 ,
        0x37 ,0x52 ,0x2d ,0x13 ,0xa4 ,0xad ,0x14 ,0xdb ,
        0xdf ,0xf6 ,0xb9 ,0x76 ,0xa5 ,0x29 ,0xd5 ,0x8d ,
        0x9c ,0xcc ,0xb5 ,0x89 ,0x92 ,0x36 ,0x8d ,0xf0 ,
        0xef ,0x91 ,0x79 ,0x8a ,0x75 ,0x61 ,0x79 ,0x11 ,
        0x88 ,0xce ,0x9b ,0x89 ,0x16 ,0x24 ,0x47 ,0x15 };
    
    unsigned char private_key1[32] = {
        0x57 ,0x47 ,0x55 ,0xe8 ,0x39 ,0x3d ,0x53 ,0x48 ,
        0x46 ,0x1c ,0xe1 ,0xae ,0x65 ,0x97 ,0x73 ,0x65 ,
        0xeb ,0x7b ,0xc7 ,0x3f ,0x61 ,0x5b ,0xf1 ,0x26 ,
        0x16 ,0x0f ,0xff ,0xe2 ,0x79 ,0xd5 ,0xd3 ,0xd7};
    
    
    
    
    unsigned char public_key2[64] = {
        0x04 ,0xb8 ,0xb0 ,0x1d ,0xc7 ,0x3a ,0x34 ,0xc7 ,
        0x53 ,0x0c ,0xe0 ,0xab ,0xa4 ,0xf1 ,0x53 ,0x98 ,
        0xe7 ,0x13 ,0x7a ,0x76 ,0x82 ,0x07 ,0x8b ,0xac ,
        0x25 ,0x4a ,0x86 ,0x79 ,0x73 ,0x0b ,0x4e ,0xed ,
        0x5d ,0x98 ,0x5c ,0x36 ,0x55 ,0x8e ,0x78 ,0x5b ,
        0x7c ,0xf2 ,0x6a ,0xbf ,0x65 ,0xb4 ,0x73 ,0x0b ,
        0x12 ,0x88 ,0x9d ,0x0e ,0xa0 ,0x8d ,0xa9 ,0x52 ,
        0x8a ,0xe1 ,0xfd ,0x0a ,0x24 ,0x22 ,0x18 ,0xf7};
    
    unsigned char private_key2[32] = {
        0x72 ,0xf8 ,0x5b ,0x36 ,0xab ,0x28 ,0x57 ,0x29 ,
        0xe5 ,0x55 ,0x05 ,0xb4 ,0x3f ,0x8a ,0xdd ,0xb4 ,
        0x03 ,0x75 ,0xed ,0x56 ,0x31 ,0xce ,0x4b ,0x85 ,
        0x60 ,0x16 ,0x55 ,0x17 ,0x3a ,0xd1 ,0xfa ,0xce};
    
    
    unsigned char share[32] = {
        0x76 ,0xf1 ,0xdd ,0x99 ,0x5e ,0xce ,0x32 ,0x5e ,
        0x65 ,0xfe ,0xab ,0xc4 ,0x92 ,0xc8 ,0xe9 ,0x2e ,
        0x20 ,0x31 ,0x88 ,0x73 ,0xac ,0x17 ,0xc1 ,0x7d ,
        0x42 ,0x1e ,0x3b ,0x9a ,0x1b ,0x6b ,0xea ,0x20 };
    
    unsigned char *share1;
    akc_calculate_ecdh(&share1, public_key2, private_key1);
    if (byte_cmp(share1, share, 32)!=0) {
        printf("\n sm2ECDH_TEST,share1!=share");
        return -1;
    }
    unsigned char *share2;
    akc_calculate_ecdh(&share2, public_key1, private_key2);
    if (byte_cmp(share2, share, 32)!=0) {
        printf("\n sm2ECDH_TEST,share2!=share");
        return -1;
    }
    if (byte_cmp(share2, share1, 32)!=0) {
        printf("\n sm2ECDH_TEST,share2!=share1");
        return -1;
    }
    return 0;
}

int randomTest(char *outpath)
{
    
    FILE *f;
    if( ( f = fopen( outpath, "w+" ) ) == NULL )
        return( -1 );
    
    int res = 0;
    unsigned char random[32] = {0};
    float α = 0.01;
    
    unsigned char all_freq_monobit_res[1000] = {0};
    unsigned char all_freq_block_res[1000] = {0};
    unsigned char all_run_res[1000] = {0};
    unsigned char all_runs_one_block_res[1000] = {0};

    
    for (int i=0; i<1000; i++) {
        fprintf(f, "index : %d \n", i);
        
        genRandomString(random,32);
        
        //单比特频数检测
        float freq_monobit_res = freq_monobit(random, 32);
        all_freq_monobit_res[i] = (freq_monobit_res >= α);
        fprintf(f, "freq_monobit_res : %f", freq_monobit_res);
        fprintf(f, " pass : %d\n", all_freq_monobit_res[i]);
        
       
        //块内频数
        float freq_block_res =  freq_block(random, 32, 4);
        all_freq_block_res[i] = (freq_block_res >= α);
        fprintf(f, "freq_block_res : %f", freq_block_res);
        fprintf(f, " pass : %d\n", all_freq_block_res[i]);
        
        
        //游程总数检测
        float run_res =  runs(random, 32);
        all_run_res[i] = (run_res >= α);
        fprintf(f, "run_res : %f", run_res);
        fprintf(f, " pass : %d\n", all_run_res[i]);
        
       
        //块内最大1游程检测
        float runs_one_block_res =  runs_one_block(random,32,SMALL_BLOCK);
        all_runs_one_block_res[i] = (runs_one_block_res >= α);
        fprintf(f, "runs_one_block_res : %f", runs_one_block_res);
        fprintf(f, " pass : %d\n", all_runs_one_block_res[i]);
        
        fputs("\n", f);
       
        memset(random, 0, AKC_KEY_LEN);
    }
    
   

    double freq_monobit_res_passingrate = (double)byte_add(all_freq_monobit_res, 1000)/1000;
    double freq_block_res_passingrate = (double)byte_add(all_freq_block_res, 1000)/1000;
    double run_res_passingrate = (double)byte_add(all_run_res, 1000)/1000;
    double runs_one_block_res_passingrate = (double)byte_add(all_runs_one_block_res, 1000)/1000;

    fprintf(f, "freq_monobit_res_passingrate : %f\n", freq_monobit_res_passingrate);
    fprintf(f, "freq_block_res_passingrate : %f\n", freq_block_res_passingrate);
    fprintf(f, "run_res_passingrate : %f\n", run_res_passingrate);
    fprintf(f, "runs_one_block_res_passingrate : %f\n", runs_one_block_res_passingrate);
    
    memset(all_freq_monobit_res, 0, 1000);
    memset(all_freq_block_res, 0, 1000);
    memset(all_run_res, 0, 1000);
    memset(all_runs_one_block_res, 0, 1000);

    
    if (!(freq_monobit_res_passingrate>=0.98 && freq_block_res_passingrate>=0.98 && run_res_passingrate>=0.98 && runs_one_block_res_passingrate>=0.98)) {
        res =  -1;
    }
    
    fclose( f );
    f = NULL;
    return res;
}

int genRandomString(unsigned char* ouput,int length)
{
    sfmt_t sfmt;
    sfmt_init_gen_rand(&sfmt, (unsigned)time( NULL ) + rand());
    int i;
    for (i = 0; i < length; i++)
    {
        ouput[i] = sfmt_genrand_uint32(&sfmt);
    }
    return 0;
}

int akc_generate_key_pair(unsigned char **public_key, unsigned char **private_key)
{
    int result = 0;
    unsigned char *key_private = 0;
    unsigned char *key_public = 0;
    unsigned char private[AKC_KEY_LEN];
    unsigned char randomkey[AKC_KEY_LEN];
    result = genRandomString(randomkey,32);
    EccPoint public;
    result = ecc_make_key(&public, private, randomkey);
    if(result < 0) {
        goto complete;
    }
    //合并public，前32位public.x，后32位public.y
    key_public = malloc(AKC_PUBLIC_KEY_LEN);
    memcpy(key_public, public.x , AKC_KEY_LEN);
    memcpy(key_public + AKC_KEY_LEN, public.y , AKC_KEY_LEN);
    key_private = malloc(AKC_KEY_LEN);
    memcpy(key_private, private , AKC_KEY_LEN);
complete:
    if(result >= 0) {
        *private_key = key_private;
        *public_key = key_public;
    }
    return result;
}

/**
 * 公私钥ECDH算法
 *
 *
 * @param shared_key_data DH值
 * @param public_key 公钥
 * @param private_key 私钥
 * reuturn shared_key_data 长度
 */
int akc_calculate_ecdh(unsigned char **shared_key_data, const unsigned char *public_key, const unsigned char *private_key)
{
    unsigned char *shared_secret = 0;
    unsigned char p_secret[AKC_KEY_LEN];
    EccPoint p_publicKey;
    unsigned char p_random[AKC_KEY_LEN];
    int result = 0;
    if(!public_key || !private_key) {
        return result;
    }
    result = genRandomString(p_random,32);
    
    //切割public_key，前32位public.x，后32位public.y，给p_publicKey赋值
    memcpy(p_publicKey.x, public_key, AKC_KEY_LEN);
    memcpy(p_publicKey.y, public_key+AKC_KEY_LEN, AKC_KEY_LEN);
    
    result = ecdh_shared_secret(p_secret, &p_publicKey,(unsigned char*) private_key, p_random);
    if(result > 0) {
        shared_secret = malloc(AKC_KEY_LEN);
        memcpy(shared_secret, p_secret , AKC_KEY_LEN);
        *shared_key_data = shared_secret;
        return AKC_KEY_LEN;
    }
    else {
        return result;
    }
}

/**
 * ECDH算法 sender
 *
 *
 * @param shared_ecdh_out DH值
 * @param my_idka 我的私钥
 * @param my_otpka 我的选取的onetimekey私钥
 * @param their_spkb 对方签名公钥
 * @param their_idkb 对方id公钥
 * @param their_otpkb 对方onetimekey公钥
 * reuturn shared_ecdh_out 长度
 */
int akc_sender_ecdh(unsigned char **shared_ecdh_out,
                          const unsigned char *my_idka,
                          const unsigned char *my_otpka,
                          const unsigned char *their_spkb,
                          const unsigned char *their_idkb,
                          const unsigned char *their_otpkb)
{
    int result = 0;
    
    int dh1len = 0;
    int dh2len = 0;
    int dh3len = 0;
    int dh4len = 0;

    unsigned char *dh1 = 0 ;
    unsigned char *dh2 = 0 ;
    unsigned char *dh3 = 0 ;
    unsigned char *dh4 = 0 ;

    dh1len = akc_calculate_ecdh(&dh1, their_spkb ,my_idka);
    if (dh1len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh2len = akc_calculate_ecdh(&dh2, their_idkb, my_otpka);
    if (dh2len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh3len = akc_calculate_ecdh(&dh3, their_spkb, my_otpka);
    if (dh3len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh4len = akc_calculate_ecdh(&dh4, their_otpkb, my_otpka);
    if (dh4len <= 0) {
        result = -1;
        goto complete;
    }
complete:
    if(result >= 0) {
        int totallen = dh1len + dh2len + dh3len + dh4len;
        unsigned char * ecdh = malloc(totallen);
        memcpy(ecdh, dh1 , dh1len);
        memcpy(ecdh + dh1len, dh2 , dh2len);
        memcpy(ecdh + dh1len + dh2len, dh3 , dh3len);
        memcpy(ecdh + dh1len + dh2len + dh3len, dh4 , dh4len);
        *shared_ecdh_out = ecdh;
        return totallen;
    }
    return result;
}

/**
 * ECDH算法 receiver
 *
 *
 * @param shared_ecdh_out DH值
 * @param their_idkb 对方id公钥
 * @param their_otpkb 对方onetimekey公钥
 * @param my_spka 我的签名私钥
 * @param my_idka 我的id私钥
 * @param my_otpka 我的onetimekey私钥
 * reuturn shared_ecdh_out 长度
 */
int akc_receiver_ecdh(unsigned char **shared_ecdh_out,
                            const unsigned char *their_idkb,
                            const unsigned char *their_otpkb,
                            const unsigned char *my_spka,
                            const unsigned char *my_idka,
                            const unsigned char *my_otpka)
{
    int result = 0;
    
    int dh1len = 0;
    int dh2len = 0;
    int dh3len = 0;
    int dh4len = 0;
    
    unsigned char *dh1 = 0 ;
    unsigned char *dh2 = 0 ;
    unsigned char *dh3 = 0 ;
    unsigned char *dh4 = 0 ;
    
    dh1len = akc_calculate_ecdh(&dh1, their_idkb ,my_spka);
    if (dh1len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh2len = akc_calculate_ecdh(&dh2, their_otpkb, my_idka);
    if (dh2len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh3len = akc_calculate_ecdh(&dh3, their_otpkb, my_spka);
    if (dh3len <= 0) {
        result = -1;
        goto complete;
    }
    
    dh4len = akc_calculate_ecdh(&dh4, their_otpkb, my_otpka);
    if (dh4len <= 0) {
        result = -1;
        goto complete;
    }
complete:
    if(result >= 0) {
        int totallen = dh1len + dh2len + dh3len + dh4len;
        unsigned char * ecdh = malloc(totallen);
        memcpy(ecdh, dh1 , dh1len);
        memcpy(ecdh + dh1len, dh2 , dh2len);
        memcpy(ecdh + dh1len + dh2len, dh3 , dh3len);
        memcpy(ecdh + dh1len + dh2len + dh3len, dh4 , dh4len);
        *shared_ecdh_out = ecdh;
        return totallen;
    }
    return result;
}

int akc_sender_root_key(const unsigned char *my_idka,
                         const unsigned char *my_otpka,
                         const unsigned char *their_spkb,
                         const unsigned char *their_idkb,
                         const unsigned char *their_otpkb,
                         unsigned char **root_key_out)
{
    unsigned char *root_dh = 0;
    int sender_ecdh_len = akc_sender_ecdh(&root_dh, my_idka, my_otpka, their_spkb, their_idkb, their_otpkb);
    unsigned char output[AKC_KEY_LEN] = {0};
    sm3(root_dh,sender_ecdh_len, output);
    unsigned char * key = malloc(AKC_KEY_LEN);
    memcpy(key, output , AKC_KEY_LEN);
    memset(output, 0, AKC_KEY_LEN);
    *root_key_out = key;
    if (root_dh) free(root_dh);
    return AKC_KEY_LEN;
}

int akc_receiver_root_key(const unsigned char *their_idkb,
                           const unsigned char *their_otpkb,
                           const unsigned char *my_spka,
                           const unsigned char *my_idka,
                           const unsigned char *my_otpka,
                           unsigned char **root_key_out)
{
    unsigned char *root_dh = 0;
    int receiver_ecdh_len = akc_receiver_ecdh(&root_dh, their_idkb, their_otpkb, my_spka, my_idka, my_otpka);
    unsigned char output[AKC_KEY_LEN] = {0};
    sm3(root_dh,receiver_ecdh_len, output);
    unsigned char * key = malloc(AKC_KEY_LEN);
    memcpy(key, output , AKC_KEY_LEN);
    memset(output, 0, AKC_KEY_LEN);
    *root_key_out = key;
    if (root_dh) free(root_dh);
    return AKC_KEY_LEN;
}

int akc_chain_key(const unsigned char *root_chain_key, int count,unsigned char **chain_key_out)
{
    int len = 0;
    if (count <= 1) {
        len = akc_chain_key_next(root_chain_key, chain_key_out);
    }else {
        unsigned char *key_chain = malloc(AKC_KEY_LEN);
        unsigned char *root_temp =  malloc(AKC_KEY_LEN);
        memcpy(root_temp, root_chain_key , AKC_KEY_LEN);
        for (int i=0; i<count; i++) {
            memset(key_chain, 0, len);
            len = akc_chain_key_next(root_temp, &key_chain);
            memset(root_temp, 0, len);
            memcpy(root_temp, key_chain , AKC_KEY_LEN);
        }
        *chain_key_out = key_chain;
        if (root_temp) free(root_temp);
    }
    return len;
}

int akc_chain_key_next( const unsigned char *chain_key, unsigned char **chain_key_next_out)
{
    unsigned char output[AKC_KEY_LEN] = {0};
    sm3((unsigned char*)chain_key,AKC_KEY_LEN, output);
    unsigned char * key = malloc(AKC_KEY_LEN);
    memcpy(key, output , AKC_KEY_LEN);
    *chain_key_next_out = key;
    memset(output, 0, AKC_KEY_LEN);
    return AKC_KEY_LEN;
}

int akc_message_headkey(const unsigned char *my_idka,
                        const unsigned char *their_idkb,
                        unsigned char **key_out)
{
    akc_calculate_ecdh(key_out, their_idkb ,my_idka);
    return 1;
}

int akc_message_mf(const unsigned char *mfplain,
                   size_t mflen,
                   unsigned char **mf_out)
{
    unsigned char message_mf[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)mfplain,(int)mflen, message_mf);
    unsigned char * mf = malloc(AKC_KEY_LEN);
    memcpy(mf, message_mf , AKC_KEY_LEN);
    *mf_out = mf;
    return 1;
}

int akc_message_HMAC(const unsigned char *input,
                     size_t inlen,
                     const unsigned char *mackey,
                     unsigned char **hmac_out)
{
    unsigned char output[AKC_KEY_LEN] = {0};
    sm3_hmac((unsigned char*)mackey, 32, (unsigned char*)input, (int)inlen, output);
    unsigned char * hamc = malloc(AKC_KEY_LEN);
    memcpy(hamc, output , AKC_KEY_LEN);
    *hmac_out = hamc;
    return 1;
}

int akc_message_keys(const unsigned char *chain_key,
                     const unsigned char *message_mf,
                     size_t message_mf_len,
                     unsigned char **messagekey_out,
                     unsigned char **miv_out,
                     unsigned char **mac_out)
{
    unsigned char output[AKC_KEY_LEN] = {0};
    unsigned char message_mac[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)message_mf,(int)message_mf_len, message_mac);
    unsigned char * buff = malloc(AKC_KEY_LEN*2);
    memcpy(buff, chain_key , AKC_KEY_LEN);
    memcpy(buff+AKC_KEY_LEN, message_mac, AKC_KEY_LEN);
    sm3(buff,AKC_KEY_LEN*2,output);
    
    unsigned char * messagekey = malloc(AKC_MESSAGE_KEY_LEN);
    memcpy(messagekey, output , AKC_MESSAGE_KEY_LEN);
    *messagekey_out = messagekey;
    
    unsigned char * messageiv = malloc(AKC_MESSAGE_KEY_LEN);
    memcpy(messageiv, output+AKC_MESSAGE_KEY_LEN , AKC_MESSAGE_KEY_LEN);
    *miv_out = messageiv;
    
    unsigned char * messagemac = malloc(AKC_KEY_LEN);
    memcpy(messagemac, message_mac , AKC_KEY_LEN);
    *mac_out = messagemac;
    
    if (buff) free(buff);
    memset(output, 0, AKC_KEY_LEN);
    memset(message_mac, 0, AKC_KEY_LEN);
    return 1;
}

int akc_signature(const unsigned char *datasignature,
                  size_t datasignature_len,
                  unsigned char **signature_out)
{
    int result = 0;
    unsigned char *signature = 0;
    
    unsigned char randomkey[AKC_KEY_LEN];
    result = genRandomString(randomkey,32);
    
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    
    unsigned char *public_key;
    unsigned char *private_key;
    akc_generate_key_pair(&public_key, &private_key);

    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    result = ecdsa_sign(r, s, private_key, randomkey, id_hash);
    if (result == 1) {
        signature = malloc(AKC_KEY_LEN+AKC_KEY_LEN+AKC_PUBLIC_KEY_LEN);
        memcpy(signature, r , AKC_KEY_LEN);
        memcpy(signature + AKC_KEY_LEN, s , AKC_KEY_LEN);
        memcpy(signature + AKC_KEY_LEN + AKC_KEY_LEN, public_key , AKC_PUBLIC_KEY_LEN);
        *signature_out = signature;
    }
    
    memset(randomkey, 0, AKC_KEY_LEN);
    memset(r, 0, AKC_KEY_LEN);
    memset(s, 0, AKC_KEY_LEN);
    memset(id_hash, 0, AKC_KEY_LEN);
    if (public_key) free(public_key);
    if (private_key) free(private_key);
    
    return result;
}

int akc_verify_signature(const unsigned char *datasignature,
                         size_t datasignature_len,
                         const unsigned char *signature)
{
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    unsigned char public_key[AKC_PUBLIC_KEY_LEN];
    memcpy(r, signature, AKC_KEY_LEN);
    memcpy(s, signature+AKC_KEY_LEN, AKC_KEY_LEN);
    memcpy(public_key, signature+AKC_KEY_LEN+AKC_KEY_LEN, AKC_PUBLIC_KEY_LEN);
    
    EccPoint p_publicKey;
    //切割public_key，前32位public.x，后32位public.y，给p_publicKey赋值
    memcpy(p_publicKey.x, (unsigned char *)public_key, AKC_KEY_LEN);
    memcpy(p_publicKey.y, (unsigned char *)public_key+AKC_KEY_LEN, AKC_KEY_LEN);
    
    int res =  ecdsa_verify(&p_publicKey, id_hash, r, s);
    
    memset(id_hash, 0, AKC_KEY_LEN);
    memset(r, 0, AKC_KEY_LEN);
    memset(s, 0, AKC_KEY_LEN);
    memset(public_key, 0, AKC_PUBLIC_KEY_LEN);
    memset(&p_publicKey, 0, sizeof(EccPoint));

    return res;
}

size_t akc_encrypt_withpublickey(const unsigned char *input,
                                 size_t inlen,
                                 const unsigned char *publickey,
                                 unsigned char **output)
{
    unsigned char *tmp_public_key;
    unsigned char *tmp_private_key;
    akc_generate_key_pair(&tmp_public_key, &tmp_private_key);
    
    unsigned char *share;
    akc_calculate_ecdh(&share, publickey, tmp_private_key);
    unsigned char key[AKC_MESSAGE_KEY_LEN];
    unsigned char iv[AKC_IV_LEN];
    memcpy(key, share, AKC_MESSAGE_KEY_LEN);
    memcpy(iv, share+AKC_MESSAGE_KEY_LEN, AKC_IV_LEN);
    
    unsigned char *encrypt_out = 0;
    size_t encrypt_out_len = akc_sm4_encrypt(input, inlen, key, iv, &encrypt_out);
    
    unsigned char * final_encrypt_out = malloc(encrypt_out_len+AKC_PUBLIC_KEY_LEN);
    memcpy(final_encrypt_out, tmp_public_key , AKC_PUBLIC_KEY_LEN);
    memcpy(final_encrypt_out+AKC_PUBLIC_KEY_LEN, encrypt_out , encrypt_out_len);

    if (tmp_public_key) free(tmp_public_key);
    if (tmp_private_key) free(tmp_private_key);
    if (share) free(share);
    memset(key, 0, AKC_MESSAGE_KEY_LEN);
    memset(iv, 0, AKC_IV_LEN);
    
    *output = final_encrypt_out;
    return encrypt_out_len+AKC_PUBLIC_KEY_LEN;
}

size_t akc_decrypt_withprivatekey(const unsigned char *input,
                                  size_t inlen,
                                  const unsigned char *privatekey,
                                  unsigned char **output)
{
    unsigned char public_key[AKC_PUBLIC_KEY_LEN];
    unsigned char input_data[inlen-AKC_PUBLIC_KEY_LEN];
    memcpy(public_key, input, AKC_PUBLIC_KEY_LEN);
    memcpy(input_data, input+AKC_PUBLIC_KEY_LEN, inlen-AKC_PUBLIC_KEY_LEN);

    unsigned char *share;
    akc_calculate_ecdh(&share, public_key, privatekey);
    unsigned char key[AKC_MESSAGE_KEY_LEN];
    unsigned char iv[AKC_IV_LEN];
    memcpy(key, share, AKC_MESSAGE_KEY_LEN);
    memcpy(iv, share+AKC_MESSAGE_KEY_LEN, AKC_IV_LEN);
    
    size_t result = akc_sm4_decrypt(input_data, inlen-AKC_PUBLIC_KEY_LEN, key, iv, output);
    
    if (share) free(share);
    memset(key, 0, AKC_MESSAGE_KEY_LEN);
    memset(iv, 0, AKC_IV_LEN);
    memset(public_key, 0, AKC_PUBLIC_KEY_LEN);
    memset(input_data, 0, inlen-AKC_PUBLIC_KEY_LEN);
    
    return result;
}


size_t akc_sm4_encrypt(const unsigned char *input,
                              size_t inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output)
{
    size_t result = 0;
    //补位
    size_t plainInDataLength = inlen;
    size_t paddingLength = AKC_IV_LEN - plainInDataLength % AKC_IV_LEN;
    size_t encryptDataLength = plainInDataLength + paddingLength;
    unsigned char *plainInChar = (unsigned char *)malloc((encryptDataLength) * sizeof(unsigned char));
    memcpy(plainInChar, input, plainInDataLength);
    //补位内容为需要补的长度
    memset(plainInChar+plainInDataLength, paddingLength, paddingLength);
    // 输出密文 
    unsigned char *cipherOutChar = (unsigned char *)malloc(encryptDataLength * sizeof(unsigned char));
    unsigned char iv[AKC_IV_LEN];
    memcpy(iv, miv, AKC_IV_LEN);
    unsigned char sm4Key[AKC_MESSAGE_KEY_LEN];
    memcpy(sm4Key, key, AKC_MESSAGE_KEY_LEN);
    sm4_context ctx;
    sm4_setkey_enc(&ctx,sm4Key);
    sm4_crypt_cbc(&ctx, SM4_ENCRYPT, (int)encryptDataLength, iv, plainInChar, cipherOutChar);
    result = encryptDataLength;
    if (result>0) {
        unsigned char * encryptdata = malloc(result);
        memcpy(encryptdata, cipherOutChar , result);
        *output = encryptdata;
    }
    memset(plainInChar, 0, encryptDataLength);
    free(plainInChar);
    memset(cipherOutChar, 0, encryptDataLength);
    free(cipherOutChar);
    memset(iv, 0, AKC_IV_LEN);
    memset(sm4Key, 0, AKC_MESSAGE_KEY_LEN);
    return result;
}

size_t akc_sm4_decrypt(const unsigned char *input,
                              size_t inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output)
{
    size_t result = 0;
    if (inlen<=0) {
        return 0;
    }
    unsigned char iv[AKC_IV_LEN];
    memcpy(iv, miv, AKC_IV_LEN);
    unsigned char sm4Key[AKC_MESSAGE_KEY_LEN];
    memcpy(sm4Key, key, AKC_MESSAGE_KEY_LEN);
    size_t plainWithPaddingLength = inlen;
    unsigned char *plainOutChar = (unsigned char *)malloc(plainWithPaddingLength * sizeof(unsigned char));
    sm4_context ctx;
    sm4_setkey_dec(&ctx,sm4Key);
    sm4_crypt_cbc(&ctx, SM4_DECRYPT, (int)plainWithPaddingLength, iv, (unsigned char *)input, plainOutChar);
    //padding length
    size_t paddingLength  = plainOutChar[plainWithPaddingLength-1];
    if (plainWithPaddingLength > paddingLength) {
        result = plainWithPaddingLength-paddingLength;
        unsigned char * decryptdata = malloc(result);
        memcpy(decryptdata, plainOutChar , result);
        *output = decryptdata;
    }else{
        result = 0;
    }
    memset(plainOutChar, 0, plainWithPaddingLength);
    free(plainOutChar);
    memset(iv, 0, AKC_IV_LEN);
    memset(sm4Key, 0, AKC_MESSAGE_KEY_LEN);
    return result;
}


size_t akc_sm3_data(const unsigned char *input,
                    size_t inlen,
                    unsigned char **output)
{
    unsigned char sm3data[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)input,(int)inlen, sm3data);
    unsigned char * sm3 = malloc(AKC_KEY_LEN);
    memcpy(sm3, sm3data , AKC_KEY_LEN);
    *output = sm3;
    return AKC_KEY_LEN;
}

int akc_sm3_file(char *path,
                    unsigned char **output)
{
    unsigned char sm3data[AKC_KEY_LEN] = {0};
    int res = sm3_file(path, sm3data);
    unsigned char * sm3 = malloc(AKC_KEY_LEN);
    memcpy(sm3, sm3data , AKC_KEY_LEN);
    *output = sm3;
    return res;
}
