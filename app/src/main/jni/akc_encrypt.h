//
//  akc_encrypt.h
//  安司密信
//
//  Created by 薛波 on 2017/10/19.
//  Copyright © 2017年 Aegis Inc. All rights reserved.
//
#define AKC_KEY_LEN 32
#define AKC_MESSAGE_KEY_LEN 16
#define AKC_IV_LEN 16
#define MAX_FILE_DATA_BLOCK 512

//#define AKCENCRYPT_DEBUG

#ifdef ANDROID
    #include <android/log.h>
    #define LOG    "akc_encrypt"
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

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "curve25519-donna.h"
#include "sm3.h"
#include "sm4.h"

#ifndef akc_encrypt_h
#define akc_encrypt_h

#ifdef __cplusplus
extern "C" {
#endif





/**
 * 生成公私钥对
 *
 *
 * @param public_key 公钥
 * @param private_key 私钥
 * reuturn 0 成功
 */
int akc_generate_key_pair(unsigned char **public_key, unsigned char **private_key);
    
/**
 * sender rootkey生成
 *
 *
 * @param my_idka 我的私钥
 * @param my_otpka 我的选取的onetimekey私钥
 * @param their_spkb 对方签名公钥
 * @param their_idkb 对方id公钥
 * @param their_otpkb 对方onetimekey公钥
 * @param root_key_out 生成的rootkey
 @ return keylen
 */
int akc_sender_root_key(const unsigned char *my_idka,
                         const unsigned char *my_otpka,
                         const unsigned char *their_spkb,
                         const unsigned char *their_idkb,
                         const unsigned char *their_otpkb,
                         unsigned char **root_key_out);
/**
 * sender rootkey生成
 *
 *
 * @param their_idkb 对方id公钥
 * @param their_otpkb 对方onetimekey公钥
 * @param my_spka 我的签名私钥
 * @param my_idka 我的id私钥
 * @param my_otpka 我的onetimekey私钥
 * @param root_key_out 生成的rootkey
 @ return keylen
 */
int akc_receiver_root_key(const unsigned char *their_idkb,
                           const unsigned char *their_otpkb,
                           const unsigned char *my_spka,
                           const unsigned char *my_idka,
                           const unsigned char *my_otpka,
                           unsigned char **root_key_out);
    
/**
 * 滚动生成chainkey
 *
 *
 * @param root_chain_key
 * @param chain_key_next 生成的chainkey
 @ return keylen
 */
int akc_chain_key(const unsigned char *root_chain_key, int count,unsigned char **chain_key_out);
    
/**
 * 滚动生成chainkey
 *
 *
 * @param chain_key 输入
 * @param chain_key_next 生成的chainkey
 @ return keylen
 */
int akc_chain_key_next(const unsigned char *chain_key, unsigned char **chain_key_next_out);
    
/**
 * chain_key生成mkey 以及 miv
 *
 *
 * @param chain_key
 * @param chain_key_len
 * @param message_idlen 消息id长度
 * @param mkey
 * @param miv
 @ return keylen
 */
int akc_message_keys(const unsigned char *chain_key,
                     const unsigned char *message_id,
                     unsigned long message_idlen,
                     unsigned char **messagekey_out,
                     unsigned char **miv_out);
  
/**
 * 加密
 *
 *
 * @param input 输入 要加密的明文
 * @param inlen 输入长度
 * @param key
 * @param output 输出 密文
 */
unsigned long akc_sm4_encrypt(const unsigned char *input,
                              unsigned long inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output);
 
/**
 * 解密
 *
 *
 * @param input 输入 要解密密的密文
 * @param inlen 输入长度
 * @param key
 * @param output 输出 明文
 */
unsigned long akc_sm4_decrypt(const unsigned char *input,
                              unsigned long inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output);



#ifdef __cplusplus
}
#endif

#endif /* akc_encrypt_h */
