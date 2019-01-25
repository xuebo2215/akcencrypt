package com.view.akcencrypt.api;

/**
 * Created by xuebo on 2017/11/7.
 */

public class AKCEncryptWrapper {
    private static final String TAG = "AKCEncryptWrapper";
    /** load JNI so */

    static {
        System.loadLibrary("crypto");

        System.loadLibrary("akcencrypt");
    }

    private static AKCEncryptWrapper instance;

    static {
        instance = null;
    }

    private AKCEncryptWrapper()
    {
        super();
    }

    public static AKCEncryptWrapper getInstance() {
        if (instance == null) instance = new AKCEncryptWrapper();
        return instance;
    }

    /*
    * 测试SM3
    * 返回 0 success
    * */
    public native int NativeSM3ABCTEST();

    /*
    * 测试SM3HMAC
    * 返回 0 success
    * */
    public native int NativeSM3HMACTEST();

    /*
    * SM4 测试
    * 返回 0 success
    * */
    public native int NativeSM4TEST();

    /*
        * SM2 ECDH测试
        * 返回 0 success
        * */
    public native int NativeSM2ECDHTEST();
    /*
        * SM2 验签测试
        * 返回 0 success
        * */
    public native int NativeSM2VerifyTEST();

    /*
        * SM2 签名/验签测试
        * 返回 0 success
        * */
    public native int NativeSM2SignatureVerifyTEST();

    /*
        * SM2 解密测试
        * 返回 0 success
        * */
    public native int NativeSM2DecryptTEST();

    /*
        * SM2 加密/解密测试
        * 返回 0 success
        * */
    public native int NativeSM2EncryptDecryptTEST();

    /*
       * SM2 一致性测试
       * 返回 0 success
       * */
    public native int NativeSM2ConTEST();

    /*
        * radom 质量检测测试
        * 返回 0 success
        * */
    public native int NativeRandomTEST(byte[]outpath);


   /*
    测试方法
    */
    public native int NativeRandomTestFormat(byte[]outpath);
    public native int NativeSm4CBCTestFormat(byte[]outpath,byte[]outpath2);
    public native int NativeSm2GenerateTestFormat(byte[]outpath);
    public native int NativeSm2EncryptTestFormat(byte[]outpath,byte[]outpath2);
    public native int NativeSm2SignTestFormat(byte[]outpath,byte[]outpath2);
    public native int NativeSm2ECDHTestFormat(byte[]outpath,byte[]outpath2);
    public native int NativeSm3TestFormat(byte[]outpath);
    public native int NativePerformanceaTest(byte[]outpath);


    /*
        * enable 模块
        * @param deviceinfo 设备运行信息
        * */
    public native void NativeEnable(byte[]deviceinfo);

    /*
        * disable 模块
        * */
    public native void NativeDisable();

    /*
    *
    *  return 1 enable 0 disable
    * */
    public native int NativeIsEnable();


    /**
     * 生成密钥
     * @return 密钥 64 + 32 位byte数组 ,前64位公钥，后32位私钥
     */
    public native byte[] NativeGeneratekeyPair();

    /**
     * @param my_idka 我的私钥
     * @param my_otpka 我的选取的onetimekey私钥
     * @param their_spkb 对方签名公钥
     * @param their_idkb 对方id公钥
     * @param their_otpkb 对方onetimekey公钥
     * @return 32位byte数组
     */
    public native byte[] NativeSenderRootKey(byte[]my_idka,
                                             byte[]my_otpka,
                                             byte[]their_spkb,
                                             byte[]their_idkb,
                                             byte[]their_otpkb);
    /*
    *  生成receiver rootkey
    * @param their_idkb 对方id公钥
    * @param their_otpkb 对方onetimekey公钥
    * @param my_spka 我的签名私钥
    * @param my_idka 我的id私钥
    * @param my_otpka 我的onetimekey私钥
    * return32位byte数组
    * */
    public native byte[] NativeReceiverRootKey(byte[]their_idkb,
                                               byte[]their_otpkb,
                                               byte[]my_spka,
                                               byte[]my_idka,
                                               byte[]my_otpka);
    /*
    *  使用rootkey生成chainkey
    * @param root_chain_key rootkey
    * @param count 滚动次数
    * return 32位byte数组
    * */
    public native byte[] NativeChainKey(byte[]root_chain_key, int count);

    /*
    *  chain_key 往下滚一次
    * @param chain_key
    * return 32位byte数组
    * */
    public native byte[] NativeChainKeyNext(byte[]chain_key);

    /*
    * 消息头加密key
    * @param my_idka 我的id私钥
    * @param their_idkb 对方id公钥
    * return 消息头key 32位
    */
    public native byte[] NativeMessageHeadKey(byte[]my_idka,byte[]their_idkb);

    /*
     * 消息明文 + 消息ID
     * 消息特征生成
     * return 消息特征32位
     */
    public native byte[] NativeMessageMF(byte[]mf_plain);
    /*
     * 消息HMAC
     * @param input 密文
     * @param mackey 输入长度
     * return hmac_out 32位HMAC
     */
    public native byte[] NativeMessageHMAC(byte[]input,byte[]mackey);
    /*
    *  生成key和iv
    * @param chain_key
    * @param message_id  消息id byte数组
    * return  16 + 16 + 32位byte数组 16位key，16位iv ,32位mac
    * */
    public native byte[] NativeMessageKeyAndIVAndMac(byte[]chain_key,
                                                byte[]message_id);

    /**
     * 消息签名
     * @param datasignature 待签名数据
     * @param my_spka 我的签名私钥
     * @param my_spkb 我的签名公钥
     * @ Returns signature_out 签名
     */
    public native byte[] NativeSignature(byte[]datasignature,byte[]my_spka,byte[]my_spkb);

    /**
     * 消息签名验证
     * @param datasignature 待验签数据
     * @param signature 签名
     * @param their_spkb 对方签名公钥
     *  @ Returns 1 if the signature is valid, 0 if it is invalid.
     */
    public native int NativeVerifySignature(byte[]datasignature,
                                            byte[]signature,
                                            byte[]their_spkb);

    /*
    * 公钥加密
    * @param input 输入明文 byte数组
    * @param inlen  明文数组长度
    * @param key 公钥
    * return byte数组 密文
    * */
    public native byte[] NativeEncryptWithPublicKey(byte[]input,
                                                    long inlen,
                                                    byte[]publickkey);

    /*
   * 私钥解密
   * @param input 输入密文 byte数组
   * @param inlen  密文数组长度
   * @param key 私钥
   * return byte数组 密文
   * */
    public native byte[] NativeDecryptWithPrivateKey(byte[]input,
                                                     long inlen,
                                                     byte[]privatekey);


    /*
    *  加密
    * @param input 输入明文 byte数组
    * @param inlen  明文数组长度
    * @param key
    * @param iv
    * return byte数组 密文
    * */
    public native byte[] NativeEncryptData(byte[]input,
                                           long inlen,
                                           byte[]key,
                                           byte[]miv);
    /*
    *  解密
    * @param input 输入密文 byte数组
    * @param inlen  密文数组长度
    * @param key
    * @param iv
    * return byte数组 明文
    * */
    public native byte[] NativeDecryptData(byte[]input,
                                           long inlen,
                                           byte[]key,
                                           byte[]miv);

    /*
    *  解密
    * @param inputfilepath 文件路径
    * return byte数组 文件SM3
    * */
    public native byte[] NativeSM3File(byte[]inputfilepath);

    /*
    *   密钥派生
    * @param inputkeyseed 输入密钥seed
    * @param len 密钥长度
    * return byte数组 生成的密钥
    * */
    public native byte[] NativeHKDF(byte[]inputkeyseed,long len);

}
