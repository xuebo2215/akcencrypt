/**
 * \file akc_sm3.h
 */
#ifndef XYSSL_SM3_H
#define XYSSL_SM3_H
#include <stdint.h>


/**
 * \brief          SM3 context structure
 */
typedef struct
{
    uint32_t total[2];     /*!< number of bytes processed  */
    uint32_t state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */

}
akc_sm3_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM3 context setup
 *
 * \param ctx      context to be initialized
 */
void akc_sm3_starts( akc_sm3_context *ctx );

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void akc_sm3_update( akc_sm3_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void akc_sm3_finish( akc_sm3_context *ctx, unsigned char output[32] );

/**
 * \brief          Output = SM3( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   SM3 checksum result
 */
void akc_sm3( unsigned char *input, int ilen,
           unsigned char output[32]);

/**
 * \brief          Output = SM3( file contents )
 *
 * \param path     input file name
 * \param output   SM3 checksum result
 *
 * \return         0 if successful, 1 if fopen failed,
 *                 or 2 if fread failed
 */
int akc_sm3_filePath( char *path, unsigned char output[32] );

/**
 * \brief          SM3 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void akc_sm3_hmac_starts( akc_sm3_context *ctx, unsigned char *key, int keylen);

/**
 * \brief          SM3 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void akc_sm3_hmac_update( akc_sm3_context *ctx, unsigned char *input, int ilen );

/**
 * \brief          SM3 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SM3 HMAC checksum result
 */
void akc_sm3_hmac_finish( akc_sm3_context *ctx, unsigned char output[32] );

/**
 * \brief          Output = HMAC-SM3( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SM3 result
 */
void akc_sm3_hmac(unsigned char *input, int ilen,
                  unsigned char *key, int keylen,
                  unsigned char output[32] );


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */