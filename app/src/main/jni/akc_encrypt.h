//
//  akc_encrypt.h
//  安司密信
//
//  Created by 薛波 on 2017/10/19.
//  Copyright © 2017年 Aegis Inc. All rights reserved.
//

#ifndef akc_encrypt_h
#define akc_encrypt_h

#define AKC_KEY_LEN 32
#define AKC_PUBLIC_KEY_LEN 64
#define AKC_MESSAGE_KEY_LEN 16
#define AKC_IV_LEN 16
#define MAX_FILE_DATA_BLOCK 512

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif
    
// 测试方法
// 0 success
int sm3ABCTEST();
    
// 0 success
int sm4_ENCRYPT_TEST();
   
// 0 success
int sm2ECDH_TEST();

// 0 success
int sm2signature_TEST();
    
// 0 success
int randomTest(char *outpath);

    

int genRandomString(unsigned char* ouput,int length);

/**
 * 生成公私钥对
 *
 *
 * @param public_key 公钥 ，公钥共64位 前32位publicX，后32位publicY
 * @param private_key 私钥
 * reuturn 1 成功
 */
int akc_generate_key_pair(unsigned char **public_key, unsigned char **private_key);
int akc_calculate_ecdh(unsigned char **shared_key_data, const unsigned char *public_key, const unsigned char *private_key);

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
    
/*
 * 消息头加密key
 * @param my_idka 我的id私钥
 * @param their_idkb 对方id公钥
 * return 1
 */
int akc_message_headkey(const unsigned char *my_idka,
                        const unsigned char *their_idkb,
                        unsigned char **key_out);
/*
 * 消息明文 + 消息ID sm3
 * 消息特征生成
 * return 1
 */
int akc_message_mf(const unsigned char *mfplain,
                   size_t mflen,
                   unsigned char **mf_out);
/*
 * 消息HMAC
 * @param input 密文
 * @param inlen 输入长度
 * @param mackey key
 * @param hmac_out 32位HMAC
 * return 1
 */
int akc_message_HMAC(const unsigned char *input,
                     size_t inlen,
                     const unsigned char *mackey,
                     unsigned char **hmac_out);
/**
 * chain_key生成mkey 以及 miv mac
 *
 *
 * @param chain_key
 * @param chain_key_len
 * @param message_mf_len 消息特征长度
 * @param mkey 16位
 * @param miv 16位
 * @param mac 32位
 @ return 1 success
 */
int akc_message_keys(const unsigned char *chain_key,
                     const unsigned char *message_mf,
                     size_t message_mf_len,
                     unsigned char **messagekey_out,
                     unsigned char **miv_out,
                     unsigned char **mac_out);

    

/**
 * 消息签名
 * @param datasignature 待签名数据
 * @param datasignature_len
 * @param signature_out 128位签名
 @ Returns 1 if the signature generated successfully
 */
int akc_signature(const unsigned char *datasignature,
                  size_t datasignature_len,
                  unsigned char **signature_out);
/**
 * 消息签名验证
 * @param datasignature 待验签数据
 * @param signature 签名
 @ Returns 1 if the signature is valid, 0 if it is invalid.
 */
int akc_verify_signature(const unsigned char *datasignature,
                         size_t datasignature_len,
                         const unsigned char *signature);
    
size_t akc_encrypt_withpublickey(const unsigned char *input,
                                 size_t inlen,
                                 const unsigned char *publickey,
                                 unsigned char **output);
    
size_t akc_decrypt_withprivatekey(const unsigned char *input,
                                 size_t inlen,
                                 const unsigned char *privatekey,
                                 unsigned char **output);
    
/**
 * 加密
 *
 *
 * @param input 输入 要加密的明文
 * @param inlen 输入长度
 * @param key
 * @param output 输出 密文
 */
size_t akc_sm4_encrypt(const unsigned char *input,
                              size_t inlen,
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
size_t akc_sm4_decrypt(const unsigned char *input,
                              size_t inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output);
    
    
size_t akc_sm3_data(const unsigned char *input,
                    size_t inlen,
                    unsigned char **output);

int akc_sm3_file(char *path,unsigned char **output);


#ifdef __cplusplus
}
#endif

#endif /* akc_encrypt_h */
