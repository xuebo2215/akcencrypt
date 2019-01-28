/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_view_akcencrypt_api_AKCEncryptWrapper */

#ifndef _Included_com_view_akcencrypt_api_AKCEncryptWrapper
#define _Included_com_view_akcencrypt_api_AKCEncryptWrapper
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM3ABCTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM3ABCTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM3HMACTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM3HMACTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM4TEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM4TEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2ECDHTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2ECDHTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2VerifyTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2VerifyTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2SignatureVerifyTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2SignatureVerifyTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2DecryptTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2DecryptTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2EncryptDecryptTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2EncryptDecryptTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM2ConTEST
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM2ConTEST
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeRandomTEST
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeRandomTEST
  (JNIEnv *, jobject, jbyteArray);
/*
 * 数据测试
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeRandomTestFormat
        (JNIEnv *, jobject, jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm4CBCTestFormat
        (JNIEnv *, jobject, jbyteArray,jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm2GenerateTestFormat
        (JNIEnv *, jobject, jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm2EncryptTestFormat
        (JNIEnv *, jobject, jbyteArray,jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm2SignTestFormat
        (JNIEnv *, jobject, jbyteArray,jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm2ECDHTestFormat
        (JNIEnv *, jobject, jbyteArray,jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSm3TestFormat
        (JNIEnv *, jobject, jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativePerformanceaTest
        (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeEnable
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeEnable
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeDisable
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeDisable
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeIsEnable
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeIsEnable
  (JNIEnv *, jobject);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeGeneratekeyPair
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeGeneratekeyPair
  (JNIEnv *, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativePrivateFormat
        (JNIEnv *, jobject,jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativePublickFormat
        (JNIEnv *, jobject,jbyteArray);
/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSenderRootKey
 * Signature: ([B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSenderRootKey
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeReceiverRootKey
 * Signature: ([B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeReceiverRootKey
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSenderRootKey2
        (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray,jbyteArray,jbyteArray,jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeReceiverRootKey2
        (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jbyteArray,jbyteArray,jbyteArray,jbyteArray);
/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeChainKey
 * Signature: ([BI)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeChainKey
  (JNIEnv *, jobject, jbyteArray, jint);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeChainKeyNext
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeChainKeyNext
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeMessageHeadKey
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeMessageHeadKey
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeMessageMF
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeMessageMF
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeMessageHMAC
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeMessageHMAC
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeMessageKeyAndIVAndMac
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeMessageKeyAndIVAndMac
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSignature
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSignature
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeVerifySignature
 * Signature: ([B[B[B)I
 */
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeVerifySignature
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSignature2
        (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray,jbyteArray);
JNIEXPORT jint JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeVerifySignature2
        (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray,jbyteArray);


/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeEncryptWithPublicKey
 * Signature: ([BJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeEncryptWithPublicKey
  (JNIEnv *, jobject, jbyteArray, jlong, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeDecryptWithPrivateKey
 * Signature: ([BJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeDecryptWithPrivateKey
  (JNIEnv *, jobject, jbyteArray, jlong, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeEncryptData
 * Signature: ([BJ[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeEncryptData
  (JNIEnv *, jobject, jbyteArray, jlong, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeDecryptData
 * Signature: ([BJ[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeDecryptData
  (JNIEnv *, jobject, jbyteArray, jlong, jbyteArray, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeSM3File
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeSM3File
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_view_akcencrypt_api_AKCEncryptWrapper
 * Method:    NativeHKDF
 * Signature: ([BJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_view_akcencrypt_api_AKCEncryptWrapper_NativeHKDF
  (JNIEnv *, jobject, jbyteArray, jlong);

#ifdef __cplusplus
}
#endif
#endif
