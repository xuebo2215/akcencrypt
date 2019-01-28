package com.view.akcencrypt;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import com.view.akcencrypt.api.AKCEncryptWrapper;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

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
                file.delete();
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


    public static List getKeyPair() {

        byte[] key = AKCEncryptWrapper.getInstance().NativeGeneratekeyPair();
        byte[] key_public = new byte[64];
        byte[] key_private = new byte[32];
        System.arraycopy(key, 0, key_public,0, 64);
        System.arraycopy(key, 64, key_private,0, 32);
        List keypair = new ArrayList();
        keypair.add(key_private);
        keypair.add(key_public);
        return  keypair;
    }

    public  static void AKCEncryTest() throws UnsupportedEncodingException {
        //测试libakcencrypt.so库
        final AKCEncryptWrapper encryptWrapper = AKCEncryptWrapper.getInstance();

        byte[] deviceinfo = "deviceinfotest".getBytes("UTF-8");
        encryptWrapper.NativeEnable(deviceinfo);

        byte[]aliceid = "ALICE123@YAHOO.COM".getBytes("UTF-8");
        List alicekey = AKCEncryptTest.getKeyPair();
        byte[] alicekey_public = (byte[]) alicekey.get(1);
        byte[] alicekey_private = (byte[]) alicekey.get(0);
        Log.d(TAG, "aliceid lenght:\r\n" + aliceid.length);

        List aliceTmpkey = AKCEncryptTest.getKeyPair();
        byte[] aliceTmpkey_public = (byte[]) aliceTmpkey.get(1);
        byte[] aliceTmpkey_private = (byte[]) aliceTmpkey.get(0);

        byte[]bobid = "BOB123@YAHOO.COM".getBytes("UTF-8");
        List bobkey = AKCEncryptTest.getKeyPair();
        byte[] bobkey_public = (byte[]) bobkey.get(1);
        byte[] bobkey_private = (byte[]) bobkey.get(0);

        List bobTmpkey = AKCEncryptTest.getKeyPair();
        byte[] bobTmpkey_public = (byte[]) bobTmpkey.get(1);
        byte[] bobTmpkey_private = (byte[]) bobTmpkey.get(0);

        Log.d(TAG, "alicekey_public:\r\n" + AKCEncryptTest.getHexString(alicekey_public));
        Log.d(TAG, "alicekey_private:\r\n" + AKCEncryptTest.getHexString(alicekey_private));

        Log.d(TAG, "alicekey_private format:\r\n" + AKCEncryptTest.getHexString(encryptWrapper.NativePrivateFormat(alicekey_private)));
        Log.d(TAG, "alicekey_publick format:\r\n" + AKCEncryptTest.getHexString(encryptWrapper.NativePublickFormat(alicekey_public)));


        byte[] sendkey = encryptWrapper.NativeSenderRootKey2(aliceid,alicekey_private,alicekey_public,aliceTmpkey_private,aliceTmpkey_public,bobid,bobkey_public,bobTmpkey_public);
        byte[] recvkey = encryptWrapper.NativeReceiverRootKey2(bobid,bobkey_private,bobkey_public,bobTmpkey_private,bobTmpkey_public,aliceid,alicekey_public,aliceTmpkey_public);
        Log.d(TAG, "sendkey:\r\n" + AKCEncryptTest.getHexString(sendkey));
        Log.d(TAG, "recvkey:\r\n" + AKCEncryptTest.getHexString(recvkey));



        byte[]dataplain = "ALICE123@YAHOO.COMBOB123@YAHOO.COMdf32534525235GFDGDFHDHFFH====GFDSGSDGSDF".getBytes("UTF-8");
        byte[]dataSignData = encryptWrapper.NativeSignature2(aliceid,dataplain,alicekey_private,alicekey_public);
        Log.d(TAG, "dataSignData:\r\n" + AKCEncryptTest.getHexString(dataSignData));
        int verify = encryptWrapper.NativeVerifySignature2(dataplain,dataSignData,aliceid,alicekey_public);
        Log.d(TAG, "verify:\r\n" + verify);

        int verify2 = encryptWrapper.NativeVerifySignature2(dataplain,dataSignData,aliceid,alicekey_public);
        Log.d(TAG, "verify2:\r\n" + verify2);
    }

    public static byte[] getBytes(char[] chars) {
        Charset cs = Charset.forName("UTF-8");
        CharBuffer cb = CharBuffer.allocate(chars.length);
        cb.put(chars);
        cb.flip();
        ByteBuffer bb = cs.encode(cb);
        return bb.array();
    }

    public  static void AKCEncryTestRandom() throws UnsupportedEncodingException {
        for(int i=0;i<1000;i++) {
            File randomTestFile = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/random/randomTest_" + i));
            String filepath = randomTestFile.getAbsolutePath();
            char[] filepathbyte = new char[filepath.length()];
            filepath.getChars(0,filepath.length(),filepathbyte,0);
            AKCEncryptWrapper.getInstance().NativeRandomTestFormat(getBytes(filepathbyte));
        }
    }



    public  static void AKCEncryTestSm4() throws UnsupportedEncodingException {
        {
            //sm4cbc
            File sm4cbcencrypt = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM4_CBC_加密_10"));
            File sm4cbcdecrypt = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM4_CBC_解密_10"));
            String filepath1 = sm4cbcencrypt.getAbsolutePath();

            
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            String filepath2 = sm4cbcdecrypt.getAbsolutePath();
            char[] filepathbyte2 = new char[filepath2.length()];
            filepath2.getChars(0,filepath2.length(),filepathbyte2,0);
            
            AKCEncryptWrapper.getInstance().NativeSm4CBCTestFormat(getBytes(filepathbyte1),getBytes(filepathbyte2));
        }
    }
    public  static void AKCEncryTestSm2Gen() throws UnsupportedEncodingException {
        {
            //SM2GEN
            File sm2Gen = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_密钥对生成_10"));
            String filepath1 = sm2Gen.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            AKCEncryptWrapper.getInstance().NativeSm2GenerateTestFormat(getBytes(filepathbyte1));
        }
    }
    public  static void AKCEncryTestSm2EncryAndDecry() throws UnsupportedEncodingException {
        {
            //SM2 Encrypt && De
            File sm2encrypt = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_加密_5"));
            File sm2decrypt = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_解密_5"));
            String filepath1 = sm2encrypt.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            String filepath2 = sm2decrypt.getAbsolutePath();
            char[] filepathbyte2 = new char[filepath2.length()];
            filepath2.getChars(0,filepath2.length(),filepathbyte2,0);
            AKCEncryptWrapper.getInstance().NativeSm2EncryptTestFormat(getBytes(filepathbyte1),getBytes(filepathbyte2));
        }
    }
    public  static void AKCEncryTestSm2Sign() throws UnsupportedEncodingException {
        {
            //SM2 sign
            File f1 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_签名(预处理前)_5"));
            File f2 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_验签(预处理前)_5"));
            String filepath1 = f1.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            String filepath2 = f2.getAbsolutePath();
            char[] filepathbyte2 = new char[filepath2.length()];
            filepath2.getChars(0,filepath2.length(),filepathbyte2,0);
            AKCEncryptWrapper.getInstance().NativeSm2SignTestFormat(getBytes(filepathbyte1),getBytes(filepathbyte2));
        }
    }
    public  static void AKCEncryTestSm2Ecdh() throws UnsupportedEncodingException {
        {
            //SM2 ecdh
            File f1 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_密钥协商(发起方)_10"));
            File f2 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM2_密钥协商(响应方)_10"));
            String filepath1 = f1.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            String filepath2 = f2.getAbsolutePath();
            char[] filepathbyte2 = new char[filepath2.length()];
            filepath2.getChars(0,filepath2.length(),filepathbyte2,0);
            AKCEncryptWrapper.getInstance().NativeSm2ECDHTestFormat(getBytes(filepathbyte1),getBytes(filepathbyte2));
        }
    }
    public  static void AKCEncryTestSm3() throws UnsupportedEncodingException {
        {
            //SM3
            File f1 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/dataVer/SM3_杂凑算法_10"));
            String filepath1 = f1.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            AKCEncryptWrapper.getInstance().NativeSm3TestFormat(getBytes(filepathbyte1));
        }
    }
    public  static void AKCEncryTestPerformancea() throws UnsupportedEncodingException {
        {
            //性能
            File f1 = createNewFile(new File(Environment.getExternalStorageDirectory().getAbsolutePath() + "/Android/data/" + "com.view.akcencrypt.dataTest" + "/performance/performance"));
            String filepath1 = f1.getAbsolutePath();
            char[] filepathbyte1 = new char[filepath1.length()];
            filepath1.getChars(0,filepath1.length(),filepathbyte1,0);
            AKCEncryptWrapper.getInstance().NativePerformanceaTest(getBytes(filepathbyte1));
        }
    }

}
