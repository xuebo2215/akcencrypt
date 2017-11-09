//
//  akc_encrypt.c
//  安司密信
//
//  Created by 薛波 on 2017/10/19.
//  Copyright © 2017年 Aegis Inc. All rights reserved.
//

#include "akc_encrypt.h"

int genRandomString(unsigned char* ouput,int length)
{
    int flag, i;
    srand( (unsigned)time( NULL ) + rand());
    for (i = 0; i < length; i++)
    {
        flag = rand() % 3;
        switch (flag)
        {
            case 0:
                ouput[i] = 'A' + rand() % 26;
                break;
            case 1:
                ouput[i] = 'a' + rand() % 26;
                break;
            case 2:
                ouput[i] = '0' + rand() % 10;
                break;
            default:
                ouput[i] = 'x';
                break;
        }
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
    result = genRandomString(randomkey,AKC_KEY_LEN);
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
    result = genRandomString(p_random,AKC_KEY_LEN);
    
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

int akc_message_keys(const unsigned char *chain_key,
                     const unsigned char *message_id,
                     unsigned long message_idlen,
                     unsigned char **messagekey_out,
                     unsigned char **miv_out)
{
#ifdef ANDROID
    LOGD("akc_message_keys  message_idlen=%lu  strlen((const char*)message_id=%lu ", message_idlen,(unsigned long)strlen((const char*)message_id));
#endif

#ifdef AKCENCRYPT_DEBUG
    printf("akc_message_keys  message_idlen=%lu  strlen((const char*)message_id=%lu ",message_idlen,strlen((const char*)message_id));
#endif
    unsigned char output[AKC_KEY_LEN] = {0};
    unsigned char messageid[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)message_id,(int)message_idlen, messageid);
    unsigned char * buff = malloc(AKC_KEY_LEN*2);
    memcpy(buff, chain_key , AKC_KEY_LEN);
    memcpy(buff+AKC_KEY_LEN, messageid, AKC_KEY_LEN);
    sm3(buff,AKC_KEY_LEN*2,output);
    
    unsigned char * messagekey = malloc(AKC_MESSAGE_KEY_LEN);
    memcpy(messagekey, output , AKC_MESSAGE_KEY_LEN);
    *messagekey_out = messagekey;
    
    unsigned char * messageiv = malloc(AKC_MESSAGE_KEY_LEN);
    memcpy(messageiv, output+AKC_MESSAGE_KEY_LEN , AKC_MESSAGE_KEY_LEN);
    *miv_out = messageiv;
    
    if (buff) free(buff);
    memset(output, 0, AKC_KEY_LEN);
    memset(messageid, 0, AKC_KEY_LEN);
    return AKC_MESSAGE_KEY_LEN;
}

int akc_signature(const unsigned char *my_spka,
                  const unsigned char *datasignature,
                  unsigned long datasignature_len,
                  unsigned char **signature_out)
{
    int result = 0;
    unsigned char *signature = 0;
    unsigned char randomkey[AKC_KEY_LEN];
    result = genRandomString(randomkey,AKC_KEY_LEN);
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    result = ecdsa_sign(r, s, (unsigned char*)my_spka, randomkey, id_hash);
    if (result == 1) {
        signature = malloc(AKC_KEY_LEN*2);
        memcpy(signature, r , AKC_KEY_LEN);
        memcpy(signature + AKC_KEY_LEN, s , AKC_KEY_LEN);
        *signature_out = signature;
    }
    return result;
}

int akc_verify_signature(const unsigned char *their_spkb,
                         const unsigned char *datasignature,
                         unsigned long datasignature_len,
                         const unsigned char *signature)
{
    unsigned char id_hash[AKC_KEY_LEN] = {0};
    sm3((unsigned char *)datasignature,(int)datasignature_len, id_hash);
    EccPoint p_publicKey;
    //切割public_key，前32位public.x，后32位public.y，给p_publicKey赋值
    memcpy(p_publicKey.x, their_spkb, AKC_KEY_LEN);
    memcpy(p_publicKey.y, their_spkb+AKC_KEY_LEN, AKC_KEY_LEN);
    unsigned char r[AKC_KEY_LEN];
    unsigned char s[AKC_KEY_LEN];
    memcpy(r, signature, AKC_KEY_LEN);
    memcpy(s, signature+AKC_KEY_LEN, AKC_KEY_LEN);
    return ecdsa_verify(&p_publicKey, id_hash, r, s);
}

unsigned long akc_sm4_encrypt(const unsigned char *input,
                              unsigned long inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output)
{
    unsigned long result = 0;
    //补位
    size_t plainInDataLength = inlen;
    size_t paddingLength = AKC_IV_LEN - plainInDataLength % AKC_IV_LEN;
    size_t encryptDataLength = plainInDataLength + paddingLength;
    unsigned char plainInChar[encryptDataLength];
    memcpy(plainInChar, input, plainInDataLength);
    //补位内容为需要补的长度
    memset(plainInChar+plainInDataLength, paddingLength, paddingLength);
#ifdef AKCENCRYPT_DEBUG
    printf("sm4_encrypt \n plainInDataLength=%lu \n encryptDataLength=%lu \n paddingLength=%lu \n",plainInDataLength,encryptDataLength,paddingLength);
#endif
    //输出密文
    unsigned char cipherOutChar[encryptDataLength];
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
    memset(cipherOutChar, 0, encryptDataLength);
    memset(iv, 0, AKC_IV_LEN);
    memset(sm4Key, 0, AKC_MESSAGE_KEY_LEN);
    return result;
}

unsigned long akc_sm4_decrypt(const unsigned char *input,
                              unsigned long inlen,
                              const unsigned char *key,
                              const unsigned char *miv,
                              unsigned char **output)
{
    unsigned long result = 0;
    unsigned char iv[AKC_IV_LEN];
    memcpy(iv, miv, AKC_IV_LEN);
    unsigned char sm4Key[AKC_MESSAGE_KEY_LEN];
    memcpy(sm4Key, key, AKC_MESSAGE_KEY_LEN);
    size_t plainWithPaddingLength = inlen;
    unsigned char plainOutChar[plainWithPaddingLength];
    sm4_context ctx;
    sm4_setkey_dec(&ctx,sm4Key);
    sm4_crypt_cbc(&ctx, SM4_DECRYPT, (int)plainWithPaddingLength, iv, (unsigned char *)input, plainOutChar);
    result = plainWithPaddingLength;
    if (result>0) {
        //获取补位长度,移除补位
        size_t paddingLength  = plainOutChar[plainWithPaddingLength-1];
        result = plainWithPaddingLength-paddingLength;
#ifdef AKCENCRYPT_DEBUG
        printf("sm4_decrypt \n plainWithPaddingLength=%lu \n paddingLength=%lu \n plainWithOutPaddingLength=%lu \n",plainWithPaddingLength,paddingLength,result);
#endif
        unsigned char * decryptdata = malloc(result);
        memcpy(decryptdata, plainOutChar , result);
        *output = decryptdata;
    }
    memset(plainOutChar, 0, plainWithPaddingLength);
    memset(iv, 0, AKC_IV_LEN);
    memset(sm4Key, 0, AKC_MESSAGE_KEY_LEN);
    return result;
}
