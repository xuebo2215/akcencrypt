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

#ifdef ANDROID
#include <android/log.h>
#define DEBUG
#ifdef  DEBUG
#define LOG    "askey"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG,__VA_ARGS__)
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,LOG,__VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG,__VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,LOG,__VA_ARGS__)
#define LOGF(...)  __android_log_print(ANDROID_LOG_FATAL,LOG,__VA_ARGS__)
#define LOGDenc(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG,__VA_ARGS__)
#else
#define LOGDenc(...)
#define LOGD(...)
#define LOGE(...)
#endif
#endif

void printBytes(unsigned char* title, unsigned char* bytes, int len)
{
    
#if ANDROID
    
    LOGE("%s(%d)", title, len);
    int count = 0;
    int i = 0;
    unsigned char* buf[128];
    memset(buf, 0, 128);
    
    unsigned char* byte[3];
    for (i = 0; i < len; i++)
    {

        snprintf(byte,3, "%02x ", bytes[i]);
        strcat(buf, byte);
        count += 1;
        if (count == 16) {
            LOGE("%s\r\n", buf);
            memset(buf, 0, 128);
            count = 0;
        }
        
    }
    if (count < 16) {
        LOGE("%s\r\n", buf);
    }
    LOGE("\r\n");
    
#else
    
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
    
#endif
}

void printTestBytesFormat(unsigned char* title, unsigned char* bytes, int len)
{
    printf("\n========== %s ==========\n",title);
    unsigned i;
    for(i=0; i<len; i++)
    {
        printf("%02x", (unsigned)bytes[i]);
    }
    printf("\n====================\n");
}

void printStr(char* str)
{
    
#if ANDROID
    
    LOGE("\r\n");
    LOGE("%s", str);
    LOGE("\r\n");
    
#else
    
    printf("\n %s \n",str);
    
#endif
}

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



int sm3ABCTEST()
{
    int res = -1;
    
    unsigned char sm3_1[32] = {
        0x3a ,0xb9 ,0x10 ,0xcd ,0x4a ,0xd1 ,0x4e ,0xce ,
        0x9a ,0x88 ,0x53 ,0x4e ,0x09 ,0xdd ,0x9e ,0x49 ,
        0xfa ,0x68 ,0x6d ,0x3a ,0x4b ,0xa6 ,0x41 ,0xf9 ,
        0xc6 ,0x9f ,0x00 ,0x5e ,0x4c ,0x8a ,0x81 ,0xdc};
    unsigned char data[500] = {
        0x66 ,0x76 ,0x69 ,0x31 ,0x77 ,0x42 ,0x77 ,0x6b ,
        0x70 ,0x65 ,0x55 ,0x61 ,0x50 ,0x74 ,0x31 ,0x34 ,
        0x46 ,0x6a ,0x30 ,0x57 ,0x61 ,0x39 ,0x4d ,0x64 ,
        0x34 ,0x71 ,0x47 ,0x35 ,0x39 ,0x6d ,0x59 ,0x31 ,
        0x41 ,0x48 ,0x4d ,0x4f ,0x76 ,0x73 ,0x79 ,0x55 ,
        0x74 ,0x6b ,0x77 ,0x76 ,0x47 ,0x30 ,0x58 ,0x50 ,
        0x58 ,0x35 ,0x54 ,0x71 ,0x55 ,0x72 ,0x6c ,0x73 ,
        0x6e ,0x4d ,0x64 ,0x4b ,0x32 ,0x52 ,0x53 ,0x37 ,
        0x6b ,0x39 ,0x62 ,0x63 ,0x37 ,0x49 ,0x58 ,0x68 ,
        0x77 ,0x45 ,0x4e ,0x6c ,0x6a ,0x71 ,0x61 ,0x7a ,
        0x32 ,0x78 ,0x41 ,0x59 ,0x41 ,0x71 ,0x66 ,0x35 ,
        0x6d ,0x79 ,0x4e ,0x63 ,0x6a ,0x55 ,0x75 ,0x5a ,
        0x69 ,0x6d ,0x30 ,0x4f ,0x58 ,0x57 ,0x56 ,0x54 ,
        0x61 ,0x58 ,0x6a ,0x6d ,0x55 ,0x53 ,0x61 ,0x38 ,
        0x36 ,0x6a ,0x32 ,0x65 ,0x6a ,0x6b ,0x67 ,0x70 ,
        0x64 ,0x47 ,0x48 ,0x33 ,0x59 ,0x34 ,0x6d ,0x49 ,
        0x4c ,0x64 ,0x62 ,0x55 ,0x6f ,0x62 ,0x53 ,0x6c ,
        0x62 ,0x64 ,0x4f ,0x46 ,0x32 ,0x65 ,0x59 ,0x4f ,
        0x75 ,0x73 ,0x4c ,0x48 ,0x37 ,0x39 ,0x64 ,0x6b ,
        0x38 ,0x39 ,0x55 ,0x53 ,0x4f ,0x48 ,0x7a ,0x74 ,
        0x68 ,0x56 ,0x70 ,0x69 ,0x38 ,0x6d ,0x66 ,0x45 ,
        0x7a ,0x7a ,0x58 ,0x62 ,0x36 ,0x52 ,0x6d ,0x6c ,
        0x51 ,0x37 ,0x78 ,0x4f ,0x50 ,0x6e ,0x6a ,0x48 ,
        0x53 ,0x43 ,0x5a ,0x45 ,0x37 ,0x66 ,0x50 ,0x49 ,
        0x4b ,0x71 ,0x54 ,0x72 ,0x41 ,0x6f ,0x62 ,0x45 ,
        0x6a ,0x75 ,0x6e ,0x76 ,0x58 ,0x48 ,0x31 ,0x43 ,
        0x44 ,0x4b ,0x62 ,0x4e ,0x77 ,0x58 ,0x7a ,0x75 ,
        0x49 ,0x67 ,0x4b ,0x48 ,0x41 ,0x64 ,0x4c ,0x52 ,
        0x63 ,0x7a ,0x6a ,0x56 ,0x67 ,0x30 ,0x4f ,0x42 ,
        0x64 ,0x7a ,0x35 ,0x66 ,0x71 ,0x41 ,0x39 ,0x33 ,
        0x55 ,0x61 ,0x4c ,0x44 ,0x54 ,0x70 ,0x34 ,0x42 ,
        0x58 ,0x4c ,0x6b ,0x76 ,0x41 ,0x50 ,0x64 ,0x33 ,
        0x48 ,0x37 ,0x42 ,0x61 ,0x78 ,0x78 ,0x4f ,0x70 ,
        0x31 ,0x67 ,0x47 ,0x67 ,0x30 ,0x50 ,0x6f ,0x43 ,
        0x50 ,0x6a ,0x69 ,0x64 ,0x6e ,0x69 ,0x6b ,0x39 ,
        0x52 ,0x52 ,0x66 ,0x6c ,0x55 ,0x35 ,0x42 ,0x53 ,
        0x41 ,0x78 ,0x6f ,0x59 ,0x79 ,0x7a ,0x52 ,0x71 ,
        0x6a ,0x53 ,0x38 ,0x69 ,0x71 ,0x36 ,0x66 ,0x4a ,
        0x6f ,0x56 ,0x33 ,0x55 ,0x6f ,0x50 ,0x64 ,0x67 ,
        0x6d ,0x31 ,0x55 ,0x69 ,0x4e ,0x59 ,0x67 ,0x4b ,
        0x75 ,0x42 ,0x5a ,0x7a ,0x49 ,0x64 ,0x66 ,0x42 ,
        0x57 ,0x44 ,0x62 ,0x38 ,0x4c ,0x43 ,0x51 ,0x7a ,
        0x44 ,0x6a ,0x51 ,0x48 ,0x57 ,0x36 ,0x59 ,0x32 ,
        0x30 ,0x6a ,0x44 ,0x44 ,0x4b ,0x69 ,0x59 ,0x44 ,
        0x54 ,0x59 ,0x47 ,0x69 ,0x6b ,0x32 ,0x63 ,0x47 ,
        0x71 ,0x5a ,0x4d ,0x42 ,0x7a ,0x66 ,0x68 ,0x39 ,
        0x31 ,0x75 ,0x62 ,0x42 ,0x38 ,0x79 ,0x70 ,0x77 ,
        0x6d ,0x75 ,0x77 ,0x45 ,0x47 ,0x6d ,0x55 ,0x6d ,
        0x6d ,0x63 ,0x5a ,0x43 ,0x72 ,0x72 ,0x53 ,0x4a ,
        0x47 ,0x69 ,0x32 ,0x74 ,0x49 ,0x76 ,0x79 ,0x5a ,
        0x6e ,0x33 ,0x31 ,0x6e ,0x46 ,0x41 ,0x6d ,0x56 ,
        0x4b ,0x67 ,0x36 ,0x68 ,0x55 ,0x73 ,0x43 ,0x68 ,
        0x55 ,0x79 ,0x79 ,0x50 ,0x4a ,0x4e ,0x48 ,0x6e ,
        0x43 ,0x48 ,0x5a ,0x50 ,0x41 ,0x52 ,0x47 ,0x5a ,
        0x68 ,0x57 ,0x36 ,0x63 ,0x70 ,0x55 ,0x63 ,0x46 ,
        0x68 ,0x66 ,0x67 ,0x4d ,0x4a ,0x51 ,0x49 ,0x70 ,
        0x37 ,0x34 ,0x56 ,0x31 ,0x4d ,0x79 ,0x39 ,0x46 ,
        0x50 ,0x33 ,0x58 ,0x36 ,0x4e ,0x65 ,0x51 ,0x4e ,
        0x78 ,0x52 ,0x4c ,0x66 ,0x59 ,0x75 ,0x63 ,0x37 ,
        0x30 ,0x74 ,0x76 ,0x34 ,0x63 ,0x4f ,0x4d ,0x64 ,
        0x70 ,0x79 ,0x31 ,0x52 ,0x6d ,0x70 ,0x45 ,0x57 ,
        0x59 ,0x49 ,0x75 ,0x79 ,0x6a ,0x57 ,0x61 ,0x53 ,
        0x76 ,0x71 ,0x49 ,0x47};
    unsigned char sm3data[AKC_KEY_LEN] = {0};
    sm3(data,500, sm3data);
    res = byte_cmp(sm3data, (unsigned char*)sm3_1, 32);
    memset(sm3data, 0, AKC_KEY_LEN);
    memset(sm3_1, 0, AKC_KEY_LEN);
    memset(data, 0, 500);

    if (res!=0) {
        printf("\n sm3ABCTEST FAIL");
    }
    return res;
}

/*
 SM3 HMAC的自检原理
 预置密钥 HMAC_KEY
 预置消息数据 ENCRYPT_DATA
 预置鉴别码值SM3HMAC_DATA
 
 ENCRYPT_DATA + HMAC_KEY，计算SM3_HMAC
 SM3_HMAC与预置鉴别码值SM3HMAC_DATA比较,若一致则通过返回0，否则失败。
 */

int sm3HMAC_TEST()
{
    int res = -1;
    unsigned char HMAC_KEY[32] = {0xeb ,0xb0 ,0xcf ,0xc6 ,0x9a ,0xe0 ,0x42 ,0xbc ,
        0xde ,0x36 ,0xff ,0x1d ,0x70 ,0xd3 ,0xfd ,0x28 ,
        0xd3 ,0x27 ,0x96 ,0x5b ,0x96 ,0x81 ,0xbd ,0x1d ,
        0x07 ,0x51 ,0x09 ,0x0f ,0x1d ,0x02 ,0x5f ,0xfb};
    
    unsigned char ENCRYPT_DATA[9] = {0xe7 ,0xa8 ,0x29 ,0xe9 ,0xce ,0x31 ,0x64 , 0xef ,0xb5};
    
    unsigned char SM3HMAC_DATA[32] = {0xe2 ,0x10 ,0x19 ,0xe3 ,0x37 ,0x5f ,0x70 ,0x0f ,
        0xb4 ,0x80 ,0x28 ,0x21 ,0xb5 ,0xac ,0x81 ,0xeb ,
        0x0a ,0xa3 ,0xf7 ,0x52 ,0x10 ,0x7a ,0x49 ,0x88 ,
        0x5c ,0xf0 ,0x9b ,0x1c ,0x8e ,0xc0 ,0x9c ,0x5c};
    
    unsigned char *hmacout = 0;
    akc_message_HMAC(ENCRYPT_DATA, 9, HMAC_KEY, &hmacout);
    res = byte_cmp(hmacout, (unsigned char*)SM3HMAC_DATA, 32);
    
    memset(HMAC_KEY, 0, 32);
    memset(ENCRYPT_DATA, 0, 9);
    memset(SM3HMAC_DATA, 0, 32);

    
    if (res!=0) {
        printf("\n sm3HMAC_TEST FAIL");
    }
    
    return res;
}

int sm4_TEST()
{
    int res = -1;
    unsigned char SM4_DECRYPT_DATA[64] = {
        0x55 ,0x49 ,0x42 ,0x65 ,0x65 ,0x56 ,0x4d ,0x49 ,
        0x70 ,0x47 ,0x38 ,0x39 ,0x6d ,0x6c ,0x35 ,0x75 ,
        0x43 ,0x53 ,0x32 ,0x68 ,0x75 ,0x4e ,0x37 ,0x46 ,
        0x74 ,0x5a ,0x74 ,0x41 ,0x33 ,0x48 ,0x76 ,0x31 ,
        0x7a ,0x4e ,0x44 ,0x49 ,0x35 ,0x4d ,0x67 ,0x30 ,
        0x67 ,0x65 ,0x64 ,0x68 ,0x32 ,0x44 ,0x62 ,0x56 ,
        0x4f ,0x59 ,0x30 ,0x56 ,0x33 ,0x52 ,0x72 ,0x4d ,
        0x6b ,0x31 ,0x38 ,0x4c ,0x6e ,0x68 ,0x44 ,0x39};
    
    unsigned char SM4_ENCRYPT_DATA[80] = {
        0x23 ,0x93 ,0x69 ,0xcf ,0x2d ,0xa7 ,0xf4 ,0x4d ,
        0xc9 ,0x4f ,0x94 ,0x5a ,0x05 ,0x5a ,0x63 ,0x16 ,
        0x48 ,0x9f ,0x77 ,0x01 ,0x6c ,0x73 ,0x70 ,0x1a ,
        0xea ,0x3f ,0xc2 ,0x46 ,0xe6 ,0xdf ,0xb5 ,0x06 ,
        0xd2 ,0x4d ,0x83 ,0x0d ,0xae ,0x0d ,0x04 ,0x23 ,
        0x54 ,0x92 ,0xa6 ,0x60 ,0xf7 ,0x12 ,0x0b ,0x51 ,
        0x77 ,0xcc ,0x41 ,0x1e ,0x39 ,0xfc ,0x00 ,0xdc ,
        0x9f ,0x46 ,0x09 ,0x41 ,0x6c ,0x9a ,0x4f ,0xf7 ,
        0x44 ,0x66 ,0xe4 ,0xcf ,0x57 ,0x48 ,0x79 ,0xc9 ,
        0x36 ,0x74 ,0x36 ,0x2e ,0xc5 ,0xae ,0x4d ,0x5e };
    
    unsigned char KEY[16] = {0x95, 0x8E, 0x72, 0xE6, 0x3C, 0x1B, 0x65, 0xD3, 0x25, 0xAC, 0xF7, 0xF6, 0x50, 0xAF, 0xBA, 0x75};
    unsigned char IV[16] = {0x32, 0x5E, 0x22, 0x47, 0x58, 0xB0, 0x7C, 0x10, 0x66, 0xBB, 0xC1, 0x5A, 0xC5, 0x46, 0x89, 0xED};
    
    unsigned char *encryptoutput = 0;
    size_t encrypt_len =  akc_sm4_encrypt(SM4_DECRYPT_DATA, 64, KEY, IV, &encryptoutput);
    res = byte_cmp(encryptoutput, (unsigned char*)SM4_ENCRYPT_DATA, (int)encrypt_len);
    if (res!=0) {
        printf("\n sm4_TEST,ENCRYPT FAIL");
    }
    
    unsigned char *decryptoutput = 0;
    size_t decrypt_len =  akc_sm4_decrypt(encryptoutput, encrypt_len, KEY, IV, &decryptoutput);
    res = byte_cmp(decryptoutput, (unsigned char*)SM4_DECRYPT_DATA, (int)decrypt_len);
    if (res!=0) {
        printf("\n sm4_TEST,DECRYPT FAIL");
    }
    
    if (encryptoutput) free(encryptoutput);
    if (decryptoutput) free(decryptoutput);
    
    memset(SM4_DECRYPT_DATA, 0, 64);
    memset(SM4_ENCRYPT_DATA, 0, 80);
    memset(KEY, 0, 16);
    memset(IV, 0, 16);
    return res;
}

int sm2_verify_TEST()
{
    int res = -1;
    unsigned char data[64] = {
        0x42 ,0x77 ,0x69 ,0x33 ,0x64 ,0x71 ,0x73 ,0x32 ,
        0x74 ,0x56 ,0x62 ,0x30 ,0x31 ,0x57 ,0x73 ,0x79 ,
        0x48 ,0x66 ,0x46 ,0x49 ,0x35 ,0x67 ,0x64 ,0x4c ,
        0x67 ,0x49 ,0x39 ,0x4e ,0x66 ,0x47 ,0x63 ,0x77 ,
        0x69 ,0x70 ,0x4d ,0x4b ,0x30 ,0x4f ,0x32 ,0x43 ,
        0x75 ,0x6e ,0x4c ,0x42 ,0x46 ,0x4b ,0x64 ,0x4d ,
        0x54 ,0x75 ,0x50 ,0x73 ,0x4e ,0x75 ,0x4d ,0x6b ,
        0x78 ,0x76 ,0x48 ,0x37 ,0x64 ,0x55 ,0x66 ,0x55};
    
    unsigned char public_key[64] = {
        0x54 ,0xad ,0xaf ,0x16 ,0x19 ,0x86 ,0xeb ,0x9f ,
        0x2b ,0xf0 ,0x26 ,0xac ,0xba ,0x30 ,0xc6 ,0x1d ,
        0x39 ,0xf2 ,0x08 ,0x88 ,0xee ,0x43 ,0xad ,0x9c ,
        0xab ,0x91 ,0x99 ,0x6f ,0x61 ,0x70 ,0x74 ,0xd2 ,
        0x54 ,0xbe ,0xa1 ,0xa3 ,0xf5 ,0x48 ,0x6b ,0x39 ,
        0x45 ,0x21 ,0x49 ,0x5d ,0xbe ,0x4e ,0x81 ,0x7c ,
        0x9e ,0x2c ,0x5a ,0x51 ,0xc8 ,0x6b ,0xa1 ,0x61 ,
        0x79 ,0xc2 ,0x68 ,0x3b ,0xb0 ,0x1e ,0x89 ,0xa9};
    
  
    unsigned char signature_data[65] = {
        0xcd ,0x58 ,0xea ,0xfa ,0xcf ,0xd8 ,0x2e ,0x82 ,
        0xe5 ,0x74 ,0x93 ,0x84 ,0x80 ,0x33 ,0x6b ,0x41 ,
        0x3d ,0x04 ,0x57 ,0xf1 ,0xe0 ,0x11 ,0x35 ,0xc5 ,
        0x20 ,0xe2 ,0x0e ,0x28 ,0x24 ,0x2e ,0xa9 ,0xb6 ,
        0x95 ,0x00 ,0xf8 ,0xa4 ,0xb5 ,0xeb ,0x60 ,0x3d ,
        0x82 ,0x20 ,0x4d ,0x7d ,0x75 ,0x5d ,0x27 ,0x96 ,
        0x7f ,0xbd ,0xaf ,0x42 ,0x48 ,0xe1 ,0xce ,0x48 ,
        0xb3 ,0x75 ,0xc8 ,0xfe ,0x83 ,0x15 ,0x8e ,0x33 ,
        0x01
    };
    
    res = akc_verify_signature_with_publickey(data, 64, signature_data, 65, public_key);
    if (res != 1) {
        printf("\n sm2_verify_TEST,VERIFY FAIL");
    }else{
        res = 0;
    }

    memset(data, 0, 64);
    memset(public_key, 0, 64);
    memset(signature_data, 0, 65);
    return res;
}

int sm2_signature_verify_TEST()
{
    int res = -1;
    unsigned char data[64] = {
        0x42 ,0x77 ,0x69 ,0x33 ,0x64 ,0x71 ,0x73 ,0x32 ,
        0x74 ,0x56 ,0x62 ,0x30 ,0x31 ,0x57 ,0x73 ,0x79 ,
        0x48 ,0x66 ,0x46 ,0x49 ,0x35 ,0x67 ,0x64 ,0x4c ,
        0x67 ,0x49 ,0x39 ,0x4e ,0x66 ,0x47 ,0x63 ,0x77 ,
        0x69 ,0x70 ,0x4d ,0x4b ,0x30 ,0x4f ,0x32 ,0x43 ,
        0x75 ,0x6e ,0x4c ,0x42 ,0x46 ,0x4b ,0x64 ,0x4d ,
        0x54 ,0x75 ,0x50 ,0x73 ,0x4e ,0x75 ,0x4d ,0x6b ,
        0x78 ,0x76 ,0x48 ,0x37 ,0x64 ,0x55 ,0x66 ,0x55};
    
    unsigned char public_key[64] = {
        0x54 ,0xad ,0xaf ,0x16 ,0x19 ,0x86 ,0xeb ,0x9f ,
        0x2b ,0xf0 ,0x26 ,0xac ,0xba ,0x30 ,0xc6 ,0x1d ,
        0x39 ,0xf2 ,0x08 ,0x88 ,0xee ,0x43 ,0xad ,0x9c ,
        0xab ,0x91 ,0x99 ,0x6f ,0x61 ,0x70 ,0x74 ,0xd2 ,
        0x54 ,0xbe ,0xa1 ,0xa3 ,0xf5 ,0x48 ,0x6b ,0x39 ,
        0x45 ,0x21 ,0x49 ,0x5d ,0xbe ,0x4e ,0x81 ,0x7c ,
        0x9e ,0x2c ,0x5a ,0x51 ,0xc8 ,0x6b ,0xa1 ,0x61 ,
        0x79 ,0xc2 ,0x68 ,0x3b ,0xb0 ,0x1e ,0x89 ,0xa9};
    
    unsigned char private_key[32] = {
        0x7d ,0xb9 ,0x98 ,0x97 ,0x97 ,0x20 ,0x08 ,0x37 ,
        0xfd ,0xac ,0xf0 ,0xd6 ,0xfb ,0xeb ,0x27 ,0xa3 ,
        0xb0 ,0x2d ,0xc5 ,0x40 ,0x80 ,0x25 ,0xf0 ,0x9b ,
        0x32 ,0x25 ,0xb2 ,0xda ,0x86 ,0x4c ,0x98 ,0xf9};
    

    unsigned char *signature_out = 0;
    size_t signature_out_len = akc_signature_with_privatekey(data, 64, private_key, NULL, &signature_out);
    res = akc_verify_signature_with_publickey(data, 64, signature_out, signature_out_len, public_key);
    if (res != 1) {
        printf("\n sm2_signature_verify_TEST,SIGNATURE && VERIFY FAIL");
    }else{
        res = 0;
    }
    
    memset(data, 0, 64);
    memset(public_key, 0, 64);
    memset(private_key, 0, 32);
    if (signature_out) free(signature_out);
    return res;
}

int sm2_decrypt_TEST()
{
    int res = -1;
    
    unsigned char data[64] = {
        0x48 ,0x73 ,0x72 ,0x69 ,0x6c ,0x38 ,0x6a ,0x4a ,
        0x35 ,0x79 ,0x73 ,0x35 ,0x6a ,0x68 ,0x58 ,0x72 ,
        0x54 ,0x6b ,0x6c ,0x53 ,0x46 ,0x51 ,0x56 ,0x57 ,
        0x58 ,0x6b ,0x68 ,0x41 ,0x74 ,0x55 ,0x34 ,0x4a ,
        0x31 ,0x67 ,0x6b ,0x73 ,0x44 ,0x37 ,0x5a ,0x70 ,
        0x53 ,0x36 ,0x57 ,0x6f ,0x6c ,0x65 ,0x63 ,0x6f ,
        0x6a ,0x53 ,0x69 ,0x49 ,0x41 ,0x77 ,0x54 ,0x70 ,
        0x77 ,0x36 ,0x78 ,0x66 ,0x75 ,0x55 ,0x47 ,0x4b};
    
    unsigned char encrypted_data[144] = {
        0x68 ,0x31 ,0x91 ,0x0c ,0x18 ,0x3a ,0xd3 ,0xf5 ,
        0x25 ,0xe7 ,0x5c ,0x4c ,0x52 ,0xab ,0x4f ,0x04 ,
        0x81 ,0x33 ,0x12 ,0xe5 ,0xd7 ,0x1a ,0x98 ,0xa1 ,
        0x92 ,0x7a ,0xf3 ,0xad ,0x12 ,0x4e ,0xee ,0x45 ,
        0x6c ,0xb2 ,0xc7 ,0xce ,0x45 ,0xd7 ,0xd6 ,0xf3 ,
        0x08 ,0xc6 ,0x7b ,0x02 ,0x0a ,0x73 ,0x6b ,0x03 ,
        0x2c ,0xb2 ,0x8c ,0xa3 ,0x9f ,0x1e ,0x99 ,0x4a ,
        0xce ,0x42 ,0x9b ,0xd5 ,0x8d ,0x90 ,0x86 ,0x80 ,
        0x89 ,0xf4 ,0x67 ,0x1d ,0xf3 ,0x48 ,0xb2 ,0xda ,
        0x37 ,0x21 ,0x97 ,0x25 ,0x2c ,0xe8 ,0xb6 ,0x70 ,
        0xe1 ,0xa8 ,0xfa ,0x39 ,0xf3 ,0xc4 ,0x0e ,0xc8 ,
        0xf1 ,0x71 ,0xea ,0xda ,0x88 ,0x72 ,0x0b ,0xa2 ,
        0xce ,0x13 ,0xef ,0xe4 ,0x47 ,0x67 ,0x9a ,0x06 ,
        0x83 ,0xb4 ,0x04 ,0x71 ,0x85 ,0xf4 ,0xc9 ,0x71 ,
        0x05 ,0xb0 ,0x25 ,0x09 ,0xdf ,0xa2 ,0xa5 ,0xf8 ,
        0xf9 ,0xd5 ,0x6a ,0x01 ,0xe8 ,0xca ,0x6b ,0x3d ,
        0xe7 ,0x26 ,0x0a ,0x7c ,0x95 ,0x2a ,0xaa ,0x1e ,
        0xc0 ,0x3f ,0x71 ,0xa5 ,0x6e ,0xe2 ,0xa3 ,0xd3};
    
    unsigned char private_key[32] = {
        0x57 ,0x47 ,0x55 ,0xe8 ,0x39 ,0x3d ,0x53 ,0x48 ,
        0x46 ,0x1c ,0xe1 ,0xae ,0x65 ,0x97 ,0x73 ,0x65 ,
        0xeb ,0x7b ,0xc7 ,0x3f ,0x61 ,0x5b ,0xf1 ,0x26 ,
        0x16 ,0x0f ,0xff ,0xe2 ,0x79 ,0xd5 ,0xd3 ,0xd7};
    
    unsigned char *decrypt_out = 0;
    size_t decrypt_out_len = akc_decrypt_withprivatekey(encrypted_data, 144, private_key, &decrypt_out);
    res = byte_cmp(decrypt_out, data, (int)decrypt_out_len);
    if (res!=0) {
        printf("\n sm2_decrypt_TEST,DECRYPT FAIL");
    }
    if (decrypt_out) free(decrypt_out);
    
    memset(data, 0, 64);
    memset(private_key, 0, 32);
    memset(encrypted_data, 0, 144);
    return res;
}

int sm2_encrypt_decrypt_TEST()
{
    int res = -1;
    
    unsigned char data[64] = {
        0x48 ,0x73 ,0x72 ,0x69 ,0x6c ,0x38 ,0x6a ,0x4a ,
        0x35 ,0x79 ,0x73 ,0x35 ,0x6a ,0x68 ,0x58 ,0x72 ,
        0x54 ,0x6b ,0x6c ,0x53 ,0x46 ,0x51 ,0x56 ,0x57 ,
        0x58 ,0x6b ,0x68 ,0x41 ,0x74 ,0x55 ,0x34 ,0x4a ,
        0x31 ,0x67 ,0x6b ,0x73 ,0x44 ,0x37 ,0x5a ,0x70 ,
        0x53 ,0x36 ,0x57 ,0x6f ,0x6c ,0x65 ,0x63 ,0x6f ,
        0x6a ,0x53 ,0x69 ,0x49 ,0x41 ,0x77 ,0x54 ,0x70 ,
        0x77 ,0x36 ,0x78 ,0x66 ,0x75 ,0x55 ,0x47 ,0x4b};
  
    unsigned char public_key[64] = {
        0x21 ,0x8e,0x5a ,0x72 ,0xbb ,0x5a ,0x7b ,0x0e ,
        0x67 ,0x3b ,0x7f ,0x94 ,0x05 ,0xe9 ,0x49 ,0x76 ,
        0x40 ,0x2c ,0x08 ,0x03 ,0x61 ,0x14 ,0xa5 ,0x85 ,
        0x37 ,0x52 ,0x2d ,0x13 ,0xa4 ,0xad ,0x14 ,0xdb ,
        0xdf ,0xf6 ,0xb9 ,0x76 ,0xa5 ,0x29 ,0xd5 ,0x8d ,
        0x9c ,0xcc ,0xb5 ,0x89 ,0x92 ,0x36 ,0x8d ,0xf0 ,
        0xef ,0x91 ,0x79 ,0x8a ,0x75 ,0x61 ,0x79 ,0x11 ,
        0x88 ,0xce ,0x9b ,0x89 ,0x16 ,0x24 ,0x47 ,0x15 };
    
    unsigned char private_key[32] = {
        0x57 ,0x47 ,0x55 ,0xe8 ,0x39 ,0x3d ,0x53 ,0x48 ,
        0x46 ,0x1c ,0xe1 ,0xae ,0x65 ,0x97 ,0x73 ,0x65 ,
        0xeb ,0x7b ,0xc7 ,0x3f ,0x61 ,0x5b ,0xf1 ,0x26 ,
        0x16 ,0x0f ,0xff ,0xe2 ,0x79 ,0xd5 ,0xd3 ,0xd7};
    
    unsigned char *encrypt_out = 0;
    size_t encrypt_out_len = akc_encrypt_withpublickey(data, 64, public_key, &encrypt_out);
    unsigned char *decrypt_out2 = 0;
    size_t decrypt_out2_len = akc_decrypt_withprivatekey(encrypt_out, encrypt_out_len, private_key, &decrypt_out2);
    res = byte_cmp(decrypt_out2, data, (int)decrypt_out2_len);
    if (res!=0) {
        printf("\n sm2_encrypt_decrypt_TEST,ENCRYPT && DECRYPT FAIL");
    }
    if (decrypt_out2) free(decrypt_out2);
    if (encrypt_out) free(encrypt_out);

    memset(data, 0, 64);
    memset(public_key, 0, 64);
    memset(private_key, 0, 32);
    return res;
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
    
    memset(public_key1, 0, 64);
    memset(private_key1, 0, 32);
    memset(public_key2, 0, 64);
    memset(private_key2, 0, 32);
    
    return 0;
}

//一致性测试
/*
 1、生成一对SM2加解密公私钥、一对SM2签名公私钥
 2、验证用加解密公私钥对一组数据进行加密，再解密，与原文比对，确保正确后，认为公私钥对配对一致。
 3、验证用签名公私钥对对一组数据进行签名，再验签，确保正确后，认为公私钥对配对一致。
 */
int sm2CON_TEST()
{
    int res = -1;
    unsigned char data[64] = {
        0x65 ,0x66 ,0x48 ,0x74 ,0x76 ,0x58 ,0x67 ,0x66 ,
        0x69 ,0x54 ,0x74 ,0x71 ,0x66 ,0x67 ,0x73 ,0x44 ,
        0x4f ,0x6f ,0x41 ,0x74 ,0x36 ,0x4d ,0x43 ,0x33 ,
        0x56 ,0x6b ,0x65 ,0x74 ,0x36 ,0x54 ,0x4f ,0x33 ,
        0x73 ,0x74 ,0x47 ,0x50 ,0x61 ,0x70 ,0x5a ,0x65 ,
        0x58 ,0x38 ,0x65 ,0x75 ,0x6f ,0x34 ,0x42 ,0x6b ,
        0x68 ,0x49 ,0x51 ,0x35 ,0x69 ,0x33 ,0x4b ,0x72 ,
        0x78 ,0x73 ,0x35 ,0x62 ,0x45 ,0x78 ,0x6e ,0x38};
    
    unsigned char *encrypt_public_key;
    unsigned char *encrypt_private_key;
    akc_generate_key_pair(&encrypt_public_key, &encrypt_private_key);
    unsigned char *encrypt_out = 0;
    size_t encrypt_out_len = akc_encrypt_withpublickey(data, 64, encrypt_public_key, &encrypt_out);
    unsigned char *decrypt_out = 0;
    size_t decrypt_out_len = akc_decrypt_withprivatekey(encrypt_out, encrypt_out_len, encrypt_private_key, &decrypt_out);
    res = byte_cmp(decrypt_out, data, (int)decrypt_out_len);
    if (res!=0) {
        printf("\n sm2CON_TEST,ENCRYPT && DECRYPT FAIL");
    }else{
        res = 0;
    }
    if (encrypt_public_key) free(encrypt_public_key);
    if (encrypt_private_key) free(encrypt_private_key);
    if (decrypt_out) free(decrypt_out);
    if (encrypt_out) free(encrypt_out);
    
    
    unsigned char *sign_public_key;
    unsigned char *sign_private_key;
    akc_generate_key_pair(&sign_public_key, &sign_private_key);
    unsigned char *signature_out = 0;
    size_t signature_out_len = akc_signature_with_privatekey(data, 64, sign_private_key, NULL, &signature_out);
    res = akc_verify_signature_with_publickey(data, 64, signature_out, signature_out_len, sign_public_key);
    if (res != 1) {
        printf("\n sm2CON_TEST,SIGNATURE && VERIFY FAIL");
    }else{
        res = 0;
    }
    if (sign_public_key) free(sign_public_key);
    if (sign_private_key) free(sign_private_key);
    if (signature_out) free(signature_out);
    
    return res;
}

int randomTest(char *outpath)
{
    
    FILE *f = NULL;
    if( outpath && ( f = fopen( outpath, "w+" ) ) == NULL )
        return( -1 );
    
    int res = 0;
    unsigned char random[32] = {0};
    float a = 0.01;
    
    unsigned char all_freq_monobit_res[1000] = {0};
    unsigned char all_freq_block_res[1000] = {0};
    unsigned char all_run_res[1000] = {0};
    unsigned char all_runs_one_block_res[1000] = {0};

    
    for (int i=0; i<1000; i++) {
        if (f != NULL) fprintf(f, "index : %d \n", i);
        else printf("index : %d \n", i);
        
        genRandomString(random,32);
        
        //单比特频数检测
        float freq_monobit_res = freq_monobit(random, 32);
        all_freq_monobit_res[i] = (freq_monobit_res >= a);
        if (f != NULL) fprintf(f, "freq_monobit_res : %f", freq_monobit_res);
        else printf("freq_monobit_res : %f", freq_monobit_res);

        if (f != NULL) fprintf(f, " pass : %d\n", all_freq_monobit_res[i]);
        else printf(" pass : %d\n", all_freq_monobit_res[i]);

       
        //块内频数
        float freq_block_res =  freq_block(random, 32, 4);
        all_freq_block_res[i] = (freq_block_res >= a);
        if (f != NULL) fprintf(f, "freq_block_res : %f", freq_block_res);
        else printf("freq_block_res : %f", freq_block_res);

        if (f != NULL) fprintf(f, " pass : %d\n", all_freq_block_res[i]);
        else printf(" pass : %d\n", all_freq_block_res[i]);

        
        //游程总数检测
        float run_res =  runs(random, 32);
        all_run_res[i] = (run_res >= a);
        if (f != NULL) fprintf(f, "run_res : %f", run_res);
        else printf("run_res : %f", run_res);
        
        if (f != NULL) fprintf(f, " pass : %d\n", all_run_res[i]);
        else printf(" pass : %d\n", all_run_res[i]);

       
        //块内最大1游程检测
        float runs_one_block_res =  runs_one_block(random,32,SMALL_BLOCK);
        all_runs_one_block_res[i] = (runs_one_block_res >= a);
        if (f != NULL) fprintf(f, "runs_one_block_res : %f", runs_one_block_res);
        else printf("runs_one_block_res : %f", runs_one_block_res);
        
        if (f != NULL) fprintf(f, " pass : %d\n", all_runs_one_block_res[i]);
        else printf(" pass : %d\n", all_runs_one_block_res[i]);

        if (f != NULL) fputs("\n", f);
       
        memset(random, 0, AKC_KEY_LEN);
    }
    
   

    double freq_monobit_res_passingrate = (double)byte_add(all_freq_monobit_res, 1000)/1000;
    double freq_block_res_passingrate = (double)byte_add(all_freq_block_res, 1000)/1000;
    double run_res_passingrate = (double)byte_add(all_run_res, 1000)/1000;
    double runs_one_block_res_passingrate = (double)byte_add(all_runs_one_block_res, 1000)/1000;

    if (f != NULL) fprintf(f, "freq_monobit_res_passingrate : %f\n", freq_monobit_res_passingrate);
    else printf("freq_monobit_res_passingrate : %f\n", freq_monobit_res_passingrate);

    if (f != NULL) fprintf(f, "freq_block_res_passingrate : %f\n", freq_block_res_passingrate);
    else printf("freq_block_res_passingrate : %f\n", freq_block_res_passingrate);

    if (f != NULL) fprintf(f, "run_res_passingrate : %f\n", run_res_passingrate);
    else printf("run_res_passingrate : %f\n", run_res_passingrate);

    if (f != NULL) fprintf(f, "runs_one_block_res_passingrate : %f\n", runs_one_block_res_passingrate);
    else printf("runs_one_block_res_passingrate : %f\n", runs_one_block_res_passingrate);

    
    
    memset(all_freq_monobit_res, 0, 1000);
    memset(all_freq_block_res, 0, 1000);
    memset(all_run_res, 0, 1000);
    memset(all_runs_one_block_res, 0, 1000);

    
    if (!(freq_monobit_res_passingrate>=0.98 && freq_block_res_passingrate>=0.98 && run_res_passingrate>=0.98 && runs_one_block_res_passingrate>=0.98)) {
        res =  -1;
    }
    
    if (f != NULL) fclose( f );
    f = NULL;
    return res;
}

static enum AKC_ENCRYPT_MODULE_STATE ENCRYPT_MODULE_STATE;
static int DEVICEINFOSEED;
void akc_enable(const  char *deviceinfo)
{
    ENCRYPT_MODULE_STATE = ENABLE;
    
    unsigned char seedData[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)deviceinfo,(int)strlen(deviceinfo), seedData);
    int seed=0;
    int i;
    for(i = AKC_KEY_LEN; i >= 0; --i)
    {
        seed += (seedData[i] & 0xFFFF) * (((arc4random() & 0xFFFF) << 16));
    }
    DEVICEINFOSEED = seed;
    
#ifdef AKC_CRYPT_LOG
    printBytes((unsigned char *)"seedData", seedData, 32);
    char logstr[1024];
    snprintf(logstr,1024, "akc_enable , DEVICEINFOSEED : [%d]",DEVICEINFOSEED);
    printStr(logstr);
#endif
    
    memset(seedData, 0, 32);

#ifdef AKC_CRYPT_TEST
   
    int sm3test = sm3ABCTEST();
    int sm3hmactest = sm3HMAC_TEST();
    int sm4test = sm4_TEST();
    int sm2verify = sm2_verify_TEST();
    int sm2signatureverify = sm2_signature_verify_TEST();
    int sm2Decrypt = sm2_decrypt_TEST();
    int sm2Encryptdecrypt = sm2_encrypt_decrypt_TEST();
    int sm2ECDHtest = sm2ECDH_TEST();
    int sm2CONTEST = sm2CON_TEST();
    int randomtest = randomTest(NULL);
    
    int pass = (sm3test==0 &&
                 sm3hmactest == 0 &&
                 sm4test==0 &&
                 sm2verify==0 &&
                 sm2signatureverify==0 &&
                 sm2Decrypt==0 &&
                 sm2Encryptdecrypt==0 &&
                 sm2ECDHtest==0 &&
                 sm2CONTEST==0 &&
                 randomtest==0);
    
    printf("\n akc_encrypt test pass? -> %d \n",pass);
    if (!pass) {
        printf("\n akc_encrypt test do not pass \n");
        akc_disable();
    }else{
        printf("\n akc_encrypt test pass \n");
    }
    
#endif
}

int  akc_isenable()
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        return 0;
    }
    return 1;
}

void akc_disable()
{
    ENCRYPT_MODULE_STATE = DISABLE;
}

float  akc_encryptVer()
{
    return AKC_ENCRYPT_VERSION_NUMBER;
}

int genRandomString(unsigned char* ouput,int length)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    sfmt_t sfmt;
    sfmt_init_gen_rand(&sfmt, (unsigned)time( NULL ) + arc4random() + DEVICEINFOSEED);
    int i;
    for (i = 0; i < length; i++)
    {
        ouput[i] = sfmt_genrand_uint32(&sfmt);
    }
    return 0;
}

int akc_generate_key_pair(unsigned char **public_key, unsigned char **private_key)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    unsigned char *shared_secret = 0;
    unsigned char p_secret[AKC_KEY_LEN];
    EccPoint p_publicKey;
    unsigned char p_random[AKC_KEY_LEN];
    int result = 0;
    if(!public_key || !private_key) {
        return result;
    }
    result = genRandomString(p_random,32);
    
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    akc_calculate_ecdh(key_out, their_idkb ,my_idka);
    return 1;
}

int akc_message_mf(const unsigned char *mfplain,
                   size_t mflen,
                   unsigned char **mf_out)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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

size_t akc_signature_with_privatekey(const unsigned char *datasignature,
                                  size_t datasignature_len,
                                  const unsigned char *my_spka,
                                  const unsigned char *my_spkb,
                                  unsigned char **signature_out)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    int result = 0;
    unsigned char *signature = 0;
    
    unsigned char randomkey[AKC_KEY_LEN];
    result = genRandomString(randomkey,32);
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    
    unsigned char *privatekey = malloc(AKC_KEY_LEN);
    memcpy(privatekey, my_spka , AKC_KEY_LEN);
    
    result = ecdsa_sign(r, s, privatekey, randomkey, id_hash);
    size_t signature_len = 0;
    if (result == 1) {
        if (my_spkb != NULL) {
            signature_len = (AKC_KEY_LEN + AKC_KEY_LEN + AKC_PUBLIC_KEY_LEN + 1);
        }else{
            signature_len = (AKC_KEY_LEN + AKC_KEY_LEN + 1);
        }
        signature = malloc(signature_len);
        memcpy(signature, r , AKC_KEY_LEN);
        memcpy(signature + AKC_KEY_LEN, s , AKC_KEY_LEN);
        if (my_spkb != NULL) {
            memcpy(signature + AKC_KEY_LEN + AKC_KEY_LEN, my_spkb , AKC_PUBLIC_KEY_LEN);
            memset(signature + AKC_KEY_LEN + AKC_KEY_LEN + AKC_PUBLIC_KEY_LEN , 1, 1);
        }else{
            memset(signature + AKC_KEY_LEN + AKC_KEY_LEN, 1, 1);
        }
        *signature_out = signature;
    }
    memset(randomkey, 0, AKC_KEY_LEN);
    memset(r, 0, AKC_KEY_LEN);
    memset(s, 0, AKC_KEY_LEN);
    memset(id_hash, 0, AKC_KEY_LEN);
    free(privatekey);
    if (result == 1) {
        return signature_len;
    }
    return 0;
}

int akc_verify_signature_with_publickey(const unsigned char *datasignature,
                                        size_t datasignature_len,
                                        const unsigned char *signature,
                                        size_t signature_len,
                                        const unsigned char *their_spkb)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    unsigned char public_key[AKC_PUBLIC_KEY_LEN];

#ifdef AKC_CRYPT_LOG
    printBytes((unsigned char *)"akc_verify_signature_with_publickey,signature",(unsigned char *)signature,(int)signature_len);
    char logstr[1024];
    snprintf(logstr,1024, "akc_verify_signature_with_publickey,signature_len : [%zu]",signature_len);
    printStr(logstr);
#endif

    if (their_spkb != NULL && signature_len == (AKC_KEY_LEN + AKC_KEY_LEN + AKC_PUBLIC_KEY_LEN + 1)) {
        memcpy(public_key, signature+AKC_KEY_LEN+AKC_KEY_LEN, AKC_PUBLIC_KEY_LEN);
        int ver  = signature[signature_len-1];
        
#ifdef AKC_CRYPT_LOG
        snprintf(logstr,1024, "akc_verify_signature_with_publickey,signature ver : [%d]",ver);
        printStr(logstr);
#endif

        if (ver==1) {
            if (byte_cmp((unsigned char *)their_spkb, public_key, 64)!=0) {
                memset(public_key, 0, AKC_PUBLIC_KEY_LEN);
                
#ifdef AKC_CRYPT_LOG
                printStr("akc_verify_signature_with_publickey,public_key byte_cmp their_spkb !=0");
#endif
                return -1;
            }else{
#ifdef AKC_CRYPT_LOG
                printStr("akc_verify_signature_with_publickey,public_key byte_cmp their_spkb success");
#endif
            }
        }
    }else{
        if (signature_len >= (AKC_KEY_LEN + AKC_KEY_LEN + AKC_PUBLIC_KEY_LEN)) {
            
#ifdef AKC_CRYPT_LOG
            printStr("akc_verify_signature_with_publickey,signature old");
#endif
            
            memcpy(public_key, signature+AKC_KEY_LEN+AKC_KEY_LEN, AKC_PUBLIC_KEY_LEN);
        }else if (signature_len >= (AKC_KEY_LEN + AKC_KEY_LEN)){
            int ver  = 0;
            if (signature_len == (AKC_KEY_LEN + AKC_KEY_LEN + 1)) {
                ver = signature[signature_len-1];
            }
            
#ifdef AKC_CRYPT_LOG
            snprintf(logstr,1024, "akc_verify_signature_with_publickey,signature with out publickey,signature ver : [%d]",ver);
            printStr(logstr);
#endif
            
            if (their_spkb != NULL) {
                memcpy(public_key, their_spkb, AKC_PUBLIC_KEY_LEN);
            }else{
                
#ifdef AKC_CRYPT_LOG
                printStr("akc_verify_signature_with_publickey,signature with out publickey,and their_spkb is null");
#endif
                return -2;
            }
        }
    }
    memcpy(r, signature, AKC_KEY_LEN);
    memcpy(s, signature+AKC_KEY_LEN, AKC_KEY_LEN);
    
#ifdef AKC_CRYPT_LOG
    printBytes((unsigned char *)"akc_verify_signature_with_publickey,publikkey",public_key,64);
#endif
    
    EccPoint p_publicKey;
    memcpy(p_publicKey.x, (unsigned char *)public_key, AKC_KEY_LEN);
    memcpy(p_publicKey.y, (unsigned char *)public_key+AKC_KEY_LEN, AKC_KEY_LEN);
    int res =  ecdsa_verify(&p_publicKey, id_hash, r, s);
    
#ifdef AKC_CRYPT_LOG
    snprintf(logstr,1024, "akc_verify_signature_with_publickey,signature res : [%d]",res);
    printStr(logstr);
#endif
    
    memset(id_hash, 0, AKC_KEY_LEN);
    memset(r, 0, AKC_KEY_LEN);
    memset(s, 0, AKC_KEY_LEN);
    memset(&p_publicKey, 0, sizeof(EccPoint));
    memset(public_key, 0, AKC_PUBLIC_KEY_LEN);
    return res;
}

size_t akc_encrypt_withpublickey(const unsigned char *input,
                                 size_t inlen,
                                 const unsigned char *publickey,
                                 unsigned char **output)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    unsigned char public_key[AKC_PUBLIC_KEY_LEN];
    unsigned char *input_data = (unsigned char *)malloc((inlen-AKC_PUBLIC_KEY_LEN) * sizeof(unsigned char));
    memset(input_data, 0, inlen-AKC_PUBLIC_KEY_LEN);
    
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
    if (input_data) free(input_data);

    return result;
}


size_t akc_sm4_encrypt(const unsigned char *input,
                              size_t inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
    size_t result = 0;
    size_t plainInDataLength = inlen;
    size_t paddingLength = AKC_IV_LEN - plainInDataLength % AKC_IV_LEN;
    size_t encryptDataLength = plainInDataLength + paddingLength;
    unsigned char *plainInChar = (unsigned char *)malloc((encryptDataLength) * sizeof(unsigned char));
    memcpy(plainInChar, input, plainInDataLength);
    memset(plainInChar+plainInDataLength, paddingLength, paddingLength);
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return 0;
    }
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
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return -1;
    }
    unsigned char sm3data[AKC_KEY_LEN] = {0};
    int res = sm3_file(path, sm3data);
    unsigned char * sm3 = malloc(AKC_KEY_LEN);
    memcpy(sm3, sm3data , AKC_KEY_LEN);
    *output = sm3;
    return res;
}

int AKC_HKDF(const char* cdata, size_t datalen, size_t keylen, unsigned char** keyout)
{
    if (ENCRYPT_MODULE_STATE != ENABLE) {
        printStr("ENCRYPT_MODULE_STATE ERROR");
        return -1;
    }

    int nRet = -1;
    unsigned char *pRet = NULL;
    unsigned char *pData = NULL;
    
    if(cdata==0 || datalen<=0 || keylen<=0)
    {
        return nRet;
    }
    
    pRet=(unsigned char *)malloc(keylen);
    pData=(unsigned char *)malloc(datalen+4);
   
    
    memset(pRet,  0, keylen);
    memset(pData, 0, datalen+4);
    
    unsigned char sm3hash[32]={0};
    unsigned char cCnt[4] = {0};
    int nCnt  = 1;
    int nDgst = 32;
    int nTimes = (int)(keylen+31)/32;
    int i=0;
    memcpy(pData, cdata, datalen);

#ifdef AKC_CRYPT_LOG
    char logstr[1024];
    snprintf(logstr,1024, "AKC_HKDF,nTimes : [%d]",nTimes);
    printStr(logstr);
#endif

    for(i=0; i<nTimes; i++)
    {
        {
            cCnt[0] =  (nCnt>>24) & 0xFF;
            cCnt[1] =  (nCnt>>16) & 0xFF;
            cCnt[2] =  (nCnt>> 8) & 0xFF;
            cCnt[3] =  (nCnt    ) & 0xFF;
        }
        memcpy(pData+datalen, cCnt, 4);
        sm3((unsigned char*)pData, (int)datalen+4, sm3hash);
        
        if(i == nTimes-1)
        {
            if(keylen%32 != 0)
            {
                nDgst = keylen%32;
            }
        }
#ifdef AKC_CRYPT_LOG
        printBytes((unsigned char*)"AKC_HKDF,sm3hash", sm3hash, 32);
#endif
        memcpy(pRet+32*i, sm3hash, nDgst);
        
        nCnt ++;
    }
    
    *keyout = pRet;
    nRet = 0;
    
    if(pData)free(pData);
        
    return nRet;
}

