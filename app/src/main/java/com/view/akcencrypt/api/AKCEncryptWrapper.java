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
    *  生成key和iv
    * @param chain_key
    * @param message_id  消息id byte数组
    * return 32位byte数组 前16位key，后16位iv
    * */
    public native byte[] NativeMessageKeyAndIV(byte[]chain_key,
                                               byte[]message_id);
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
        byte messageid[] = testMessageid.getBytes("UTF-8");
        Log.d(TAG, "messageid len:\r\n" + messageid.length);

        byte[] alice_send_message_key_iv = encryptWrapper.NativeMessageKeyAndIV(alice_send_chainKey,messageid);
        Log.d(TAG, "alice_send_message_key_iv:\r\n" + alice_send_message_key_iv.length);
        byte[] alice_send_message_key = new byte[16];
        byte[] alice_send_message_iv = new byte[16];
        System.arraycopy(alice_send_message_key_iv, 0, alice_send_message_key,0, 16);
        System.arraycopy(alice_send_message_key_iv, 16, alice_send_message_iv,0, 16);
        Log.d(TAG, "alice_send_message_key:\r\n" + encryptWrapper.getHexString(alice_send_message_key));
        Log.d(TAG, "alice_send_message_iv:\r\n" + encryptWrapper.getHexString(alice_send_message_iv));

        byte[] alice_recv_message_key_iv = encryptWrapper.NativeMessageKeyAndIV(alice_recv_chainKey,messageid);
        byte[] alice_recv_message_key = new byte[16];
        byte[] alice_recv_message_iv = new byte[16];
        System.arraycopy(alice_recv_message_key_iv, 0, alice_recv_message_key,0, 16);
        System.arraycopy(alice_recv_message_key_iv, 16, alice_recv_message_iv,0, 16);
        Log.d(TAG, "alice_recv_message_key:\r\n" + encryptWrapper.getHexString(alice_recv_message_key));
        Log.d(TAG, "alice_recv_message_iv:\r\n" + encryptWrapper.getHexString(alice_recv_message_iv));

        byte[] bob_send_message_key_iv = encryptWrapper.NativeMessageKeyAndIV(bob_send_chainKey,messageid);
        byte[] bob_send_message_key = new byte[16];
        byte[] bob_send_message_iv = new byte[16];
        System.arraycopy(bob_send_message_key_iv, 0, bob_send_message_key,0, 16);
        System.arraycopy(bob_send_message_key_iv, 16, bob_send_message_iv,0, 16);
        Log.d(TAG, "bob_send_message_key:\r\n" + encryptWrapper.getHexString(bob_send_message_key));
        Log.d(TAG, "bob_send_message_iv:\r\n" + encryptWrapper.getHexString(bob_send_message_iv));

        byte[] bob_recv_message_key_iv = encryptWrapper.NativeMessageKeyAndIV(bob_recv_chainKey,messageid);
        byte[] bob_recv_message_key = new byte[16];
        byte[] bob_recv_message_iv = new byte[16];
        System.arraycopy(bob_recv_message_key_iv, 0, bob_recv_message_key,0, 16);
        System.arraycopy(bob_recv_message_key_iv, 16, bob_recv_message_iv,0, 16);
        Log.d(TAG, "bob_recv_message_key:\r\n" + encryptWrapper.getHexString(bob_recv_message_key));
        Log.d(TAG, "bob_recv_message_iv:\r\n" + encryptWrapper.getHexString(bob_recv_message_iv));


        Log.d(TAG, "messageid:\r\n " + encryptWrapper.getHexString(messageid) + "orig:\r\n " + new String(messageid,"utf-8"));


        String messageplain = "中国共产党，简称中共，成立于1921年7月，1949年10月至今为代表工人阶级领导工农联盟和统一战线，在中国大陆实行人民民主专政的中华人民共和国唯一执政党。";
        byte[] messageplainbyte = messageplain.getBytes("UTF-8");

        //test encrypt
        byte alice_send_messageencrypt[] = encryptWrapper.NativeEncryptData(messageplainbyte,messageplainbyte.length,alice_send_message_key,alice_send_message_iv);
        //test deencrypt
        byte alice_send_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,alice_send_message_key,alice_send_message_iv);
        byte bob_recv_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,bob_recv_message_key,bob_recv_message_iv);
        Log.d(TAG, "alice_send_messageencrypt:\r\n" + encryptWrapper.getHexString(alice_send_messageencrypt));
        Log.d(TAG, "alice_send_messagedencrypt:\r\n" + encryptWrapper.getHexString(alice_send_messagedencrypt));
        Log.d(TAG, "bob_recv_messagedencrypt:\r\n" + encryptWrapper.getHexString(bob_recv_messagedencrypt));


        String alice_send_encrypt = new String(alice_send_messageencrypt,"utf-8");
        String alice_send_dencrypt = new String(alice_send_messagedencrypt,"utf-8");
        String bob_recv_dencrypt = new String(bob_recv_messagedencrypt,"utf-8");

        Log.d(TAG, "alice_send_encrypt:\r\n" + alice_send_encrypt);
        Log.d(TAG, "alice_send_dencrypt:\r\n" + alice_send_dencrypt);
        Log.d(TAG, "bob_recv_dencrypt:\r\n" + bob_recv_dencrypt);
    }

}
