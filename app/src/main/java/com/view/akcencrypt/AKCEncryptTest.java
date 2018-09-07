package com.view.akcencrypt;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import com.view.akcencrypt.api.AKCEncryptWrapper;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * Created by xuebo on 2018/5/24.
 */

public class AKCEncryptTest {
    private static final String TAG = "AKCEncryptTest";
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

    public static File createNewFile(File file) {

        try {

            if (file.exists()) {
                return file;
            }

            File dir = file.getParentFile();
            if (!dir.exists()) {
                dir.mkdirs();
            }
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (IOException e) {
            Log.e(TAG, "", e);
            return null;
        }
        return file;
    }

    public  static void AKCEncryTest() throws UnsupportedEncodingException {
        //测试libakcencrypt.so库
        final AKCEncryptWrapper encryptWrapper = AKCEncryptWrapper.getInstance();

        int testsm3 = encryptWrapper.NativeSM3ABCTEST();
        Log.d(TAG, "testsm3:\r\n" + testsm3);

        int sm4EncryptTest = encryptWrapper.NativeSM4ENCRYPTTEST();
        Log.d(TAG, "sm4EncryptTest:\r\n" + sm4EncryptTest);

        int sm2ECDHTest = encryptWrapper.NativeSM2ECDHTEST();
        Log.d(TAG, "sm2ECDHTest:\r\n" + sm2ECDHTest);

        int SM2SignatureTest = encryptWrapper.NativeSM2SignatureTEST();
        Log.d(TAG, "SM2SignatureTest:\r\n" + SM2SignatureTest);


        File randomTestFile =  createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath()+"/Android/data/"+"com.view.akcencrypt.test"+"/randomtest.txt"));
        if (randomTestFile.exists())
        {
            Log.d(TAG, "randomTestFile exists\r\n" );
        }else{
            Log.d(TAG, "randomTestFile not exists\r\n" );
        }

        String filepath =  randomTestFile.getAbsolutePath();
        Log.d(TAG, "filepath:\r\n" + filepath);
        byte[] filepathbyte = filepath.getBytes("UTF-8");
        int randomTest = encryptWrapper.NativeRandomTEST(filepathbyte);
        Log.d(TAG, "randomTest:\r\n" + randomTest);



        byte[] aliceid = encryptWrapper.NativeGeneratekeyPair();
        byte[] aliceid_public = new byte[64];
        byte[] aliceid_private = new byte[32];
        System.arraycopy(aliceid, 0, aliceid_public,0, 64);
        System.arraycopy(aliceid, 64, aliceid_private,0, 32);
        Log.d(TAG, "aliceid_public:\r\n" + AKCEncryptTest.getHexString(aliceid_public));
        Log.d(TAG, "aliceid_private:\r\n" + AKCEncryptTest.getHexString(aliceid_private));

        byte[] alicesign = encryptWrapper.NativeGeneratekeyPair();
        byte[] alicesign_public = new byte[64];
        byte[] alicesign_private = new byte[32];
        System.arraycopy(alicesign, 0, alicesign_public,0, 64);
        System.arraycopy(alicesign, 64, alicesign_private,0, 32);
        Log.d(TAG, "alicesign_public:\r\n" + AKCEncryptTest.getHexString(alicesign_public));
        Log.d(TAG, "alicesign_private:\r\n" + AKCEncryptTest.getHexString(alicesign_private));

        byte[] aliceopk = encryptWrapper.NativeGeneratekeyPair();
        byte[] aliceopk_public = new byte[64];
        byte[] aliceopk_private = new byte[32];
        System.arraycopy(aliceopk, 0, aliceopk_public,0, 64);
        System.arraycopy(aliceopk, 64, aliceopk_private,0, 32);
        Log.d(TAG, "aliceopk_public:\r\n" + AKCEncryptTest.getHexString(aliceopk_public));
        Log.d(TAG, "aliceopk_private:\r\n" + AKCEncryptTest.getHexString(aliceopk_private));

        byte[] bobid = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobid_public = new byte[64];
        byte[] bobid_private = new byte[32];
        System.arraycopy(bobid, 0, bobid_public,0, 64);
        System.arraycopy(bobid, 64, bobid_private,0, 32);
        Log.d(TAG, "bobid_public:\r\n" + AKCEncryptTest.getHexString(bobid_public));
        Log.d(TAG, "bobid_private:\r\n" + AKCEncryptTest.getHexString(bobid_private));

        byte[] bobsign = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobsign_public = new byte[64];
        byte[] bobsign_private = new byte[32];
        System.arraycopy(bobsign, 0, bobsign_public,0, 64);
        System.arraycopy(bobsign, 64, bobsign_private,0, 32);
        Log.d(TAG, "bobsign_public:\r\n" + AKCEncryptTest.getHexString(bobsign_public));
        Log.d(TAG, "bobsign_private:\r\n" + AKCEncryptTest.getHexString(bobsign_private));

        byte[] bobopk = encryptWrapper.NativeGeneratekeyPair();
        byte[] bobopk_public = new byte[64];
        byte[] bobopk_private = new byte[32];
        System.arraycopy(bobopk, 0, bobopk_public,0, 64);
        System.arraycopy(bobopk, 64, bobopk_private,0, 32);
        Log.d(TAG, "bobopk_public:\r\n" + AKCEncryptTest.getHexString(bobopk_public));
        Log.d(TAG, "bobopk_private:\r\n" + AKCEncryptTest.getHexString(bobopk_private));

        byte[] alice_send_root_key = encryptWrapper.NativeSenderRootKey(aliceid_private,aliceopk_private,bobsign_public,bobid_public,bobopk_public);
        byte[] alice_recv_root_key = encryptWrapper.NativeReceiverRootKey(bobid_public,bobopk_public,alicesign_private,aliceid_private,aliceopk_private);
        Log.d(TAG, "alice_send_root_key:\r\n" + AKCEncryptTest.getHexString(alice_send_root_key));
        Log.d(TAG, "alice_recv_root_key:\r\n" + AKCEncryptTest.getHexString(alice_recv_root_key));

        byte[] bob_send_root_key = encryptWrapper.NativeSenderRootKey(bobid_private,bobopk_private,alicesign_public,aliceid_public,aliceopk_public);
        byte[] bob_recv_root_key = encryptWrapper.NativeReceiverRootKey(aliceid_public,aliceopk_public,bobsign_private,bobid_private,bobopk_private);
        Log.d(TAG, "bob_send_root_key:\r\n" + AKCEncryptTest.getHexString(bob_send_root_key));
        Log.d(TAG, "bob_recv_root_key:\r\n" + AKCEncryptTest.getHexString(bob_recv_root_key));

        byte[] alice_send_chainKey = encryptWrapper.NativeChainKey(alice_send_root_key,5);
        byte[] alice_recv_chainKey = encryptWrapper.NativeChainKey(alice_recv_root_key,5);
        Log.d(TAG, "alice_send_chainKey:\r\n" + AKCEncryptTest.getHexString(alice_send_chainKey));
        Log.d(TAG, "alice_recv_chainKey:\r\n" + AKCEncryptTest.getHexString(alice_recv_chainKey));

        byte[] bob_send_chainKey = encryptWrapper.NativeChainKey(bob_send_root_key,5);
        byte[] bob_recv_chainKey = encryptWrapper.NativeChainKey(bob_recv_root_key,5);
        Log.d(TAG, "bob_send_chainKey:\r\n" + AKCEncryptTest.getHexString(bob_send_chainKey));
        Log.d(TAG, "bob_recv_chainKey:\r\n" + AKCEncryptTest.getHexString(bob_recv_chainKey));

        String testMessageid = "dfgf-dsgs-dg4";
        String messageplain = "中国共产党，简称中共，成立于1921年7月，1949年10月至今为代表工人阶级领导工农联盟和统一战线，在中国大陆实行人民民主专政的中华人民共和国唯一执政党。";
        byte[] messageplainbyte = messageplain.getBytes("UTF-8");

        byte[] messagemfPlain = (testMessageid+messageplain).getBytes("UTF-8");
        byte[] messageMF = encryptWrapper.NativeMessageMF(messagemfPlain);
        Log.d(TAG, "messageMF:\r\n" + AKCEncryptTest.getHexString(messageMF));


        byte[] alice_send_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(alice_send_chainKey,messageMF);
        Log.d(TAG, "alice_send_message_key_iv_mac:\r\n" + alice_send_message_key_iv_mac.length);
        byte[] alice_send_message_key = new byte[16];
        byte[] alice_send_message_iv = new byte[16];
        byte[] alice_send_message_mac = new byte[32];
        System.arraycopy(alice_send_message_key_iv_mac, 0, alice_send_message_key,0, 16);
        System.arraycopy(alice_send_message_key_iv_mac, 16, alice_send_message_iv,0, 16);
        System.arraycopy(alice_send_message_key_iv_mac, 32, alice_send_message_mac,0, 32);
        Log.d(TAG, "alice_send_message_key:\r\n" + AKCEncryptTest.getHexString(alice_send_message_key));
        Log.d(TAG, "alice_send_message_iv:\r\n" + AKCEncryptTest.getHexString(alice_send_message_iv));
        Log.d(TAG, "alice_send_message_mac:\r\n" + AKCEncryptTest.getHexString(alice_send_message_mac));

        byte[] alice_recv_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(alice_recv_chainKey,messageMF);
        byte[] alice_recv_message_key = new byte[16];
        byte[] alice_recv_message_iv = new byte[16];
        byte[] alice_recv_message_mac = new byte[32];
        System.arraycopy(alice_recv_message_key_iv_mac, 0, alice_recv_message_key,0, 16);
        System.arraycopy(alice_recv_message_key_iv_mac, 16, alice_recv_message_iv,0, 16);
        System.arraycopy(alice_recv_message_key_iv_mac, 32, alice_recv_message_mac,0, 32);
        Log.d(TAG, "alice_recv_message_key:\r\n" + AKCEncryptTest.getHexString(alice_recv_message_key));
        Log.d(TAG, "alice_recv_message_iv:\r\n" + AKCEncryptTest.getHexString(alice_recv_message_iv));
        Log.d(TAG, "alice_recv_message_mac:\r\n" + AKCEncryptTest.getHexString(alice_recv_message_mac));

        byte[] bob_send_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_send_chainKey,messageMF);
        byte[] bob_send_message_key = new byte[16];
        byte[] bob_send_message_iv = new byte[16];
        byte[] bob_send_message_mac = new byte[32];
        System.arraycopy(bob_send_message_key_iv_mac, 0, bob_send_message_key,0, 16);
        System.arraycopy(bob_send_message_key_iv_mac, 16, bob_send_message_iv,0, 16);
        System.arraycopy(bob_send_message_key_iv_mac, 32, bob_send_message_mac,0, 32);
        Log.d(TAG, "bob_send_message_key:\r\n" + AKCEncryptTest.getHexString(bob_send_message_key));
        Log.d(TAG, "bob_send_message_iv:\r\n" + AKCEncryptTest.getHexString(bob_send_message_iv));
        Log.d(TAG, "bob_send_message_mac:\r\n" + AKCEncryptTest.getHexString(bob_send_message_mac));

        byte[] bob_recv_message_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_recv_chainKey,messageMF);
        byte[] bob_recv_message_key = new byte[16];
        byte[] bob_recv_message_iv = new byte[16];
        byte[] bob_recv_message_mac = new byte[32];
        System.arraycopy(bob_recv_message_key_iv_mac, 0, bob_recv_message_key,0, 16);
        System.arraycopy(bob_recv_message_key_iv_mac, 16, bob_recv_message_iv,0, 16);
        System.arraycopy(bob_recv_message_key_iv_mac, 32, bob_recv_message_mac,0, 32);
        Log.d(TAG, "bob_recv_message_key:\r\n" + AKCEncryptTest.getHexString(bob_recv_message_key));
        Log.d(TAG, "bob_recv_message_iv:\r\n" + AKCEncryptTest.getHexString(bob_recv_message_iv));
        Log.d(TAG, "bob_recv_message_mac:\r\n" + AKCEncryptTest.getHexString(bob_recv_message_mac));






        //test encrypt
        byte alice_send_messageencrypt[] = encryptWrapper.NativeEncryptData(messageplainbyte,messageplainbyte.length,alice_send_message_key,alice_send_message_iv);
        //test deencrypt
        byte alice_send_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,alice_send_message_key,alice_send_message_iv);
        byte bob_recv_messagedencrypt[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,bob_recv_message_key,bob_recv_message_iv);
        Log.d(TAG, "alice_send_messageencrypt:\r\n" + AKCEncryptTest.getHexString(alice_send_messageencrypt));
        Log.d(TAG, "alice_send_messagedencrypt:\r\n" + AKCEncryptTest.getHexString(alice_send_messagedencrypt));
        Log.d(TAG, "bob_recv_messagedencrypt:\r\n" + AKCEncryptTest.getHexString(bob_recv_messagedencrypt));


        byte[] error_key_iv_mac = encryptWrapper.NativeMessageKeyAndIVAndMac(bob_recv_root_key,messageMF);
        byte[] error_key = new byte[16];
        byte[] error_iv = new byte[16];
        byte[] error_mac = new byte[32];
        System.arraycopy(error_key_iv_mac, 0, error_key,0, 16);
        System.arraycopy(error_key_iv_mac, 16, error_iv,0, 16);
        System.arraycopy(error_key_iv_mac, 32, error_mac,0, 32);
        byte error_key_test[] = encryptWrapper.NativeDecryptData(alice_send_messageencrypt,alice_send_messageencrypt.length,error_key,error_iv);
        if (error_key_test==null){
            Log.e(TAG,"error_key_test is null,NativeDecryptData ERROR");
        }
        Log.d(TAG, "error_key_test:\r\n" + AKCEncryptTest.getHexString(error_key_test));
        String error_key_test_dencrypt = new String(error_key_test,"utf-8");
        Log.d(TAG, "error_key_test_dencrypt:\r\n" + error_key_test_dencrypt);


        byte[] alicemessageHmac = encryptWrapper.NativeMessageHMAC(alice_send_messageencrypt,alice_send_message_mac);
        Log.d(TAG, "alicemessageHmac:\r\n" + AKCEncryptTest.getHexString(alicemessageHmac));
        byte[] bobmessageHmac = encryptWrapper.NativeMessageHMAC(alice_send_messageencrypt,bob_recv_message_mac);
        Log.d(TAG, "bobmessageHmac:\r\n" + AKCEncryptTest.getHexString(bobmessageHmac));

        String alice_send_encrypt = new String(alice_send_messageencrypt,"utf-8");
        String alice_send_dencrypt = new String(alice_send_messagedencrypt,"utf-8");
        String bob_recv_dencrypt = new String(bob_recv_messagedencrypt,"utf-8");

        Log.d(TAG, "alice_send_encrypt:\r\n" + alice_send_encrypt);
        Log.d(TAG, "alice_send_dencrypt:\r\n" + alice_send_dencrypt);
        Log.d(TAG, "bob_recv_dencrypt:\r\n" + bob_recv_dencrypt);

        byte signature[] = encryptWrapper.NativeSignature(alice_send_messageencrypt);
        Log.d(TAG, "signature:\r\n" + AKCEncryptTest.getHexString(signature));

        byte signature2[] = encryptWrapper.NativeSignature(alice_send_messageencrypt);
        Log.d(TAG, "signature2:\r\n" + AKCEncryptTest.getHexString(signature2));

        int ver_signature_alice = encryptWrapper.NativeVerifySignature(alice_send_messageencrypt,signature);
        Log.d(TAG, "ver_signature_alice:\r\n" + ver_signature_alice);

        int ver_signature_alice2 = encryptWrapper.NativeVerifySignature(alice_send_messageencrypt,signature2);
        Log.d(TAG, "ver_signature_alice2:\r\n" + ver_signature_alice2);

        byte[] test_verify_signature = new byte[0];
        try {
            test_verify_signature = Base64.decode("LBlL6bL+aqtWwIx2pxoDkMPzfMemngUdDzFowTVyZH8slgyhsQ7usmHjuxbrCzkT8xRbkFsdUXIPpb3x1b+Fj20Vk6Qd8gwOxKCJJii1DBkwJOt2FpRAzJxQjqoR+DnIKQ0IsCHAAs3fJbcvsxfCNoALALbE/qrShp4FBOgRXnc=");
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] test_encrypt = new byte[0];
        try {
            test_encrypt = Base64.decode("o5IjUJaFWnhjA5IouO4ULbx/3vHiPY6qMCfueJ2i6/8=");
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.d(TAG, "test_verify_signature:\r\n" + AKCEncryptTest.getHexString(test_verify_signature));
        Log.d(TAG, "test_encrypt:\r\n" + AKCEncryptTest.getHexString(test_encrypt));
        int test_ver_signature = encryptWrapper.NativeVerifySignature(test_encrypt,test_verify_signature);
        Log.d(TAG, "test_ver_signature:\r\n" + test_ver_signature);




        byte[] publickKeyEncrypTest = encryptWrapper.NativeGeneratekeyPair();
        byte[] publickKeyEncrypTest_public = new byte[64];
        byte[] publickKeyEncrypTest_private = new byte[32];
        System.arraycopy(publickKeyEncrypTest, 0, publickKeyEncrypTest_public,0, 64);
        System.arraycopy(publickKeyEncrypTest, 64, publickKeyEncrypTest_private,0, 32);

        String passcode = "passcode_test_0909";
        byte[] passcodebyte = passcode.getBytes("UTF-8");
        byte passcodeEncrybyte[] = encryptWrapper.NativeEncryptWithPublicKey(passcodebyte,passcodebyte.length,publickKeyEncrypTest_public);
        byte passcodeDecrypt[] =  encryptWrapper.NativeDecryptWithPrivateKey(passcodeEncrybyte,passcodeEncrybyte.length,publickKeyEncrypTest_private);
        String passcodeDecryptString = new String(passcodeDecrypt,"utf-8");
        Log.d(TAG, "passcodeDecryptString:\r\n" + passcodeDecryptString);

    }
}
