package com.view.akcencrypt;

import android.os.Bundle;
import android.widget.TextView;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import com.view.akcencrypt.api.AKCEncryptWrapper;
import android.util.Log;
import java.io.IOException;
import java.io.UnsupportedEncodingException;


public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }
    private static final String TAG = "AKCEncryptWrapperTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("test akcencrypt JNI");
        try {
            this.AKCEncryTest();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();



    private  void AKCEncryTest() throws IOException {
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

        byte[] test_verify_signature = Base64.decode("LBlL6bL+aqtWwIx2pxoDkMPzfMemngUdDzFowTVyZH8slgyhsQ7usmHjuxbrCzkT8xRbkFsdUXIPpb3x1b+Fj20Vk6Qd8gwOxKCJJii1DBkwJOt2FpRAzJxQjqoR+DnIKQ0IsCHAAs3fJbcvsxfCNoALALbE/qrShp4FBOgRXnc=");
        byte[] test_encrypt = Base64.decode("o5IjUJaFWnhjA5IouO4ULbx/3vHiPY6qMCfueJ2i6/8=");
        Log.d(TAG, "test_verify_signature:\r\n" + encryptWrapper.getHexString(test_verify_signature));
        Log.d(TAG, "test_encrypt:\r\n" + encryptWrapper.getHexString(test_encrypt));
        int test_ver_signature = encryptWrapper.NativeVerifySignature(test_encrypt,test_verify_signature);
        Log.d(TAG, "test_ver_signature:\r\n" + test_ver_signature);

    }
}
