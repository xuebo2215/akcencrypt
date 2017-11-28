package com.view.akcencrypt.api;

import android.util.Log;

import java.io.UnsupportedEncodingException;

/**
 * Created by xuebo on 2017/11/7.
 */

public class AKCEncryptWrapper {
    private static final String TAG = "AKCEncryptWrapper";
    /** load JNI so */

    static {
        System.loadLibrary("akcencrypt");
    }

    private static AKCEncryptWrapper instance = null;
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
    * 返回 debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
    * */
    public native byte[] NativeSM3ABCTEST();

    /*
    * SM4 加密测试
    * 返回 f3f1d0c3 dedcbfd5 6fba1bf0 9f21d44a
    * */
    public native byte[] NativeSM4ABCENCRYPTTEST();
    /*
     * SM4 解密测试
     * 返回 616263 /// UTF-8 abc
     * */
    public native byte[] NativeSM4ABCDEENCRYPTTEST(byte[]input);

    /*
    *  生成keypair
    *  return 64 + 32 位byte数组 ,前64位公钥，后32位私钥
    * */
    public native byte[] NativeGeneratekeyPair();

    /*
    *  生成sender rootkey
    * @param my_idka 我的私钥
    * @param my_otpka 我的选取的onetimekey私钥
    * @param their_spkb 对方签名公钥
    * @param their_idkb 对方id公钥
    * @param their_otpkb 对方onetimekey公钥
    * return 32位byte数组
    * */
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
     * @ Returns signature_out 128 位签名
     */
    public native byte[] NativeSignature(byte[]datasignature);

    /**
     * 消息签名验证
     * @param datasignature 待验签数据
     * @param signature 签名
     *  @ Returns 1 if the signature is valid, 0 if it is invalid.
     */
    public native int NativeVerifySignature(byte[]datasignature,
                                            byte[]signature);

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
    * getHexString
    * */
    public static String getHexString(byte[] b) {
        if (b == null) {
            return null;
        }

        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public static void AKCEncryTest() throws UnsupportedEncodingException {
        //测试libakcencrypt.so库
        final AKCEncryptWrapper encryptWrapper = AKCEncryptWrapper.getInstance();

        byte[] testsm3 = encryptWrapper.NativeSM3ABCTEST();
        Log.d(TAG, "testsm3:\r\n" + encryptWrapper.getHexString(testsm3));

        byte[] sm4EncryptTest = encryptWrapper.NativeSM4ABCENCRYPTTEST();
        Log.d(TAG, "sm4EncryptTest:\r\n" + encryptWrapper.getHexString(sm4EncryptTest));

        byte[] sm4DeEncryptTest = encryptWrapper.NativeSM4ABCDEENCRYPTTEST(sm4EncryptTest);
        String sm4DeEncryptTest_utf8String = new String(sm4DeEncryptTest,"utf-8");
        Log.d(TAG, "sm4DeEncryptTest:\r\n" + encryptWrapper.getHexString(sm4DeEncryptTest));
        Log.d(TAG, "sm4DeEncryptTest_utf8String:\r\n" + sm4DeEncryptTest_utf8String);

        byte[] aliceid = encryptWrapper.NativeGeneratekeyPair();
        byte[] aliceid_public = new byte[64];
        byte[] aliceid_private = new byte[32];
        System.arraycopy(aliceid, 0, aliceid_public,0, 64);
        System.arraycopy(aliceid, 64, aliceid_private,0, 32);
        Log.d(TAG, "aliceid_public:\r\n" + encryptWrapper.getHexString(aliceid_public));
        Log.d(TAG, "aliceid_private:\r\n" + encryptWrapper.getHexString(aliceid_private));

        byte[] alicesign = encryptWrapper.NativeGeneratekeyPair();
        byte[] alicesign_public = new byte[64];
        byte[] alicesign_private = new byte[32];
        System.arraycopy(alicesign, 0, alicesign_public,0, 64);
        System.arraycopy(alicesign, 64, alicesign_private,0, 32);
        Log.d(TAG, "alicesign_public:\r\n" + encryptWrapper.getHexString(alicesign_public));
        Log.d(TAG, "alicesign_private:\r\n" + encryptWrapper.getHexString(alicesign_private));

        byte[] aliceopk = encryptWrapper.NativeGeneratekeyPair();
        byte[] aliceopk_public = new byte[64];
        byte[] aliceopk_private = new byte[32];
        System.arraycopy(aliceopk, 0, aliceopk_public,0, 64);
        System.arraycopy(aliceopk, 64, aliceopk_private,0, 32);
        Log.d(TAG, "aliceopk_public:\r\n" + encryptWrapper.getHexString(aliceopk_public));
        Log.d(TAG, "aliceopk_private:\r\n" + encryptWrapper.getHexString(aliceopk_private));

        byte[] bobid = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobid_public = new byte[64];
        byte[] bobid_private = new byte[32];
        System.arraycopy(bobid, 0, bobid_public,0, 64);
        System.arraycopy(bobid, 64, bobid_private,0, 32);
        Log.d(TAG, "bobid_public:\r\n" + encryptWrapper.getHexString(bobid_public));
        Log.d(TAG, "bobid_private:\r\n" + encryptWrapper.getHexString(bobid_private));

        byte[] bobsign = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobsign_public = new byte[64];
        byte[] bobsign_private = new byte[32];
        System.arraycopy(bobsign, 0, bobsign_public,0, 64);
        System.arraycopy(bobsign, 64, bobsign_private,0, 32);
        Log.d(TAG, "bobsign_public:\r\n" + encryptWrapper.getHexString(bobsign_public));
        Log.d(TAG, "bobsign_private:\r\n" + encryptWrapper.getHexString(bobsign_private));

        byte[] bobopk = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobopk_public = new byte[64];
        byte[] bobopk_private = new byte[32];
        System.arraycopy(bobopk, 0, bobopk_public,0, 64);
        System.arraycopy(bobopk, 64, bobopk_private,0, 32);
        Log.d(TAG, "bobopk_public:\r\n" + encryptWrapper.getHexString(bobopk_public));
        Log.d(TAG, "bobopk_private:\r\n" + encryptWrapper.getHexString(bobopk_private));

        byte[] alice_send_root_key = encryptWrapper.NativeSenderRootKey(aliceid_private,aliceopk_private,bobsign_public,bobid_public,bobopk_public);
        byte[] alice_recv_root_key = encryptWrapper.NativeReceiverRootKey(bobid_public,bobopk_public,alicesign_private,aliceid_private,aliceopk_private);
        Log.d(TAG, "alice_send_root_key:\r\n" + encryptWrapper.getHexString(alice_send_root_key));
        Log.d(TAG, "alice_recv_root_key:\r\n" + encryptWrapper.getHexString(alice_recv_root_key));

        byte[] bob_send_root_key = encryptWrapper.NativeSenderRootKey(bobid_private,bobopk_private,alicesign_public,aliceid_public,aliceopk_public);
        byte[] bob_recv_root_key = encryptWrapper.NativeReceiverRootKey(aliceid_public,aliceopk_public,bobsign_private,bobid_private,bobopk_private);
        Log.d(TAG, "bob_send_root_key:\r\n" + encryptWrapper.getHexString(bob_send_root_key));
        Log.d(TAG, "bob_recv_root_key:\r\n" + encryptWrapper.getHexString(bob_recv_root_key));

        byte[] alice_send_chainKey = encryptWrapper.NativeChainKey(alice_send_root_key,5);
        byte[] alice_recv_chainKey = encryptWrapper.NativeChainKey(alice_recv_root_key,5);
        Log.d(TAG, "alice_send_chainKey:\r\n" + encryptWrapper.getHexString(alice_send_chainKey));
        Log.d(TAG, "alice_recv_chainKey:\r\n" + encryptWrapper.getHexString(alice_recv_chainKey));

        byte[] bob_send_chainKey = encryptWrapper.NativeChainKey(bob_send_root_key,5);
        byte[] bob_recv_chainKey = encryptWrapper.NativeChainKey(bob_recv_root_key,5);
        Log.d(TAG, "bob_send_chainKey:\r\n" + encryptWrapper.getHexString(bob_send_chainKey));
        Log.d(TAG, "bob_recv_chainKey:\r\n" + encryptWrapper.getHexString(bob_recv_chainKey));

        String testMessageid = "dfgf-dsgs-dg4";
        String messageplain = "中国共产党，简称中共，成立于1921年7月，1949年10月至今为代表工人阶级领导工农联盟和统一战线，在中国大陆实行人民民主专政的中华人民共和国唯一执政党。";
        byte[] messageplainbyte = messageplain.getBytes("UTF-8");

        byte[] messagemfPlain = (testMessageid+messageplain).getBytes("UTF-8");
        byte[] messageMF = encryptWrapper.NativeMessageMF(messagemfPlain);
        Log.d(TAG, "messageMF:\r\n" + encryptWrapper.getHexString(messageMF));


        byte[] alice_send_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(alice_send_chainKey,messageMF);
        Log.d(TAG, "alice_send_message_key_iv_mac:\r\n" + alice_send_message_key_iv_mac.length);
        byte[] alice_send_message_key = new byte[16];
        byte[] alice_send_message_iv = new byte[16];
        byte[] alice_send_message_mac = new byte[32];
        System.arraycopy(alice_send_message_key_iv_mac, 0, alice_send_message_key,0, 16);
        System.arraycopy(alice_send_message_key_iv_mac, 16, alice_send_message_iv,0, 16);
        System.arraycopy(alice_send_message_key_iv_mac, 32, alice_send_message_mac,0, 32);
        Log.d(TAG, "alice_send_message_key:\r\n" + encryptWrapper.getHexString(alice_send_message_key));
        Log.d(TAG, "alice_send_message_iv:\r\n" + encryptWrapper.getHexString(alice_send_message_iv));
        Log.d(TAG, "alice_send_message_mac:\r\n" + encryptWrapper.getHexString(alice_send_message_mac));

        byte[] alice_recv_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(alice_recv_chainKey,messageMF);
        byte[] alice_recv_message_key = new byte[16];
        byte[] alice_recv_message_iv = new byte[16];
        byte[] alice_recv_message_mac = new byte[32];
        System.arraycopy(alice_recv_message_key_iv_mac, 0, alice_recv_message_key,0, 16);
        System.arraycopy(alice_recv_message_key_iv_mac, 16, alice_recv_message_iv,0, 16);
        System.arraycopy(alice_recv_message_key_iv_mac, 32, alice_recv_message_mac,0, 32);
        Log.d(TAG, "alice_recv_message_key:\r\n" + encryptWrapper.getHexString(alice_recv_message_key));
        Log.d(TAG, "alice_recv_message_iv:\r\n" + encryptWrapper.getHexString(alice_recv_message_iv));
        Log.d(TAG, "alice_recv_message_mac:\r\n" + encryptWrapper.getHexString(alice_recv_message_mac));

        byte[] bob_send_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_send_chainKey,messageMF);
        byte[] bob_send_message_key = new byte[16];
        byte[] bob_send_message_iv = new byte[16];
        byte[] bob_send_message_mac = new byte[32];
        System.arraycopy(bob_send_message_key_iv_mac, 0, bob_send_message_key,0, 16);
        System.arraycopy(bob_send_message_key_iv_mac, 16, bob_send_message_iv,0, 16);
        System.arraycopy(bob_send_message_key_iv_mac, 32, bob_send_message_mac,0, 32);
        Log.d(TAG, "bob_send_message_key:\r\n" + encryptWrapper.getHexString(bob_send_message_key));
        Log.d(TAG, "bob_send_message_iv:\r\n" + encryptWrapper.getHexString(bob_send_message_iv));
        Log.d(TAG, "bob_send_message_mac:\r\n" + encryptWrapper.getHexString(bob_send_message_mac));

        byte[] bob_recv_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_recv_chainKey,messageMF);
        byte[] bob_recv_message_key = new byte[16];
        byte[] bob_recv_message_iv = new byte[16];
        byte[] bob_recv_message_mac = new byte[32];
        System.arraycopy(bob_recv_message_key_iv_mac, 0, bob_recv_message_key,0, 16);
        System.arraycopy(bob_recv_message_key_iv_mac, 16, bob_recv_message_iv,0, 16);
        System.arraycopy(bob_recv_message_key_iv_mac, 32, bob_recv_message_mac,0, 32);
        Log.d(TAG, "bob_recv_message_key:\r\n" + encryptWrapper.getHexString(bob_recv_message_key));
        Log.d(TAG, "bob_recv_message_iv:\r\n" + encryptWrapper.getHexString(bob_recv_message_iv));
        Log.d(TAG, "bob_recv_message_mac:\r\n" + encryptWrapper.getHexString(bob_recv_message_mac));






        //test encrypt
        byte alice_send_messageencrypt[] = encryptWrapper.NativeEncryptData(messageplainbyte,messageplainbyte.length,alice_send_message_key,alice_send_message_iv);
        //test deencrypt
        byte alice_send_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,alice_send_message_key,alice_send_message_iv);
        byte bob_recv_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,bob_recv_message_key,bob_recv_message_iv);
        Log.d(TAG, "alice_send_messageencrypt:\r\n" + encryptWrapper.getHexString(alice_send_messageencrypt));
        Log.d(TAG, "alice_send_messagedencrypt:\r\n" + encryptWrapper.getHexString(alice_send_messagedencrypt));
        Log.d(TAG, "bob_recv_messagedencrypt:\r\n" + encryptWrapper.getHexString(bob_recv_messagedencrypt));


        byte[] error_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_recv_root_key,messageMF);
        byte[] error_key = new byte[16];
        byte[] error_iv = new byte[16];
        byte[] error_mac = new byte[32];
        System.arraycopy(error_key_iv_mac, 0, error_key,0, 16);
        System.arraycopy(error_key_iv_mac, 16, error_iv,0, 16);
        System.arraycopy(error_key_iv_mac, 32, error_mac,0, 32);
        byte error_key_test[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,error_key,error_iv);
        Log.d(TAG, "error_key_test:\r\n" + encryptWrapper.getHexString(error_key_test));
        String error_key_test_dencrypt = new String(error_key_test,"utf-8");
        Log.d(TAG, "error_key_test_dencrypt:\r\n" + error_key_test_dencrypt);


        byte[] alicemessageHmac = encryptWrapper.NativeMessageHMAC(alice_send_messageencrypt,alice_send_message_mac);
        Log.d(TAG, "alicemessageHmac:\r\n" + encryptWrapper.getHexString(alicemessageHmac));
        byte[] bobmessageHmac = encryptWrapper.NativeMessageHMAC(alice_send_messageencrypt,bob_recv_message_mac);
        Log.d(TAG, "bobmessageHmac:\r\n" + encryptWrapper.getHexString(bobmessageHmac));

        String alice_send_encrypt = new String(alice_send_messageencrypt,"utf-8");
        String alice_send_dencrypt = new String(alice_send_messagedencrypt,"utf-8");
        String bob_recv_dencrypt = new String(bob_recv_messagedencrypt,"utf-8");

        Log.d(TAG, "alice_send_encrypt:\r\n" + alice_send_encrypt);
        Log.d(TAG, "alice_send_dencrypt:\r\n" + alice_send_dencrypt);
        Log.d(TAG, "bob_recv_dencrypt:\r\n" + bob_recv_dencrypt);

        byte signature[] = encryptWrapper.NativeSignature(alice_send_messageencrypt);
        Log.d(TAG, "signature:\r\n" + encryptWrapper.getHexString(signature));

        byte signature2[] = encryptWrapper.NativeSignature(alice_send_messageencrypt);
        Log.d(TAG, "signature2:\r\n" + encryptWrapper.getHexString(signature2));

        int ver_signature_alice = encryptWrapper.NativeVerifySignature(alice_send_messageencrypt,signature);
        Log.d(TAG, "ver_signature_alice:\r\n" + ver_signature_alice);

        int ver_signature_alice2 = encryptWrapper.NativeVerifySignature(alice_send_messageencrypt,signature2);
        Log.d(TAG, "ver_signature_alice2:\r\n" + ver_signature_alice2);
    }

}
