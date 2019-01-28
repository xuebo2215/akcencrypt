package com.view.akcencrypt;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.util.Log;
import android.widget.TextView;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import java.io.UnsupportedEncodingException;
import android.os.Handler;
import android.os.Message;


public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_EXTERNAL_STORAGE = 1;
    private static String[] PERMISSIONS_STORAGE = {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
    };


    public static void verifyStoragePermissions(Activity activity) {

        try {
            //检测是否有写的权限
            int permission = ActivityCompat.checkSelfPermission(activity,
                    "android.permission.WRITE_EXTERNAL_STORAGE");
            if (permission != PackageManager.PERMISSION_GRANTED) {
                // 没有写的权限，去申请写的权限，会弹出对话框
                ActivityCompat.requestPermissions(activity, PERMISSIONS_STORAGE,REQUEST_EXTERNAL_STORAGE);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Handler handler = new Handler(){
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            TextView tv = (TextView) findViewById(R.id.sample_text);
            tv.setText((String)msg.obj);
        }
    };

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }
    private static final String TAG = "AKCEncryptWrapperTestMainActivity";
    private void sendMessage(String message){
        Message ms = Message.obtain();
        ms.obj = message;
        handler.sendMessage(ms);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        verifyStoragePermissions(this);

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
            AKCEncryptTest.AKCEncryTest();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0;i< 0;i++){

                    try {
                        int taskIndex = i;
                        if (taskIndex == 0){

                            Log.d("AKCEncryptTest", "正在采集随机数\r\n");

                            sendMessage("正在采集随机数");
                            AKCEncryptTest.AKCEncryTestRandom();
                            sendMessage("采集随机数完成");

                            Log.d("AKCEncryptTest", "采集随机数完成\r\n");

                        }else if (taskIndex == 1){

                            Log.d("AKCEncryptTest", "正在采集SM4CBC\r\n");

                            sendMessage("正在采集SM4CBC");
                            AKCEncryptTest.AKCEncryTestSm4();
                            sendMessage("采集SM4CBC完成");

                            Log.d("AKCEncryptTest", "采集SM4CBC完成\r\n");

                        }else if (taskIndex == 2){

                            Log.d("AKCEncryptTest", "正在采集SM2密钥对\r\n");

                            sendMessage("正在采集SM2密钥对");
                            AKCEncryptTest.AKCEncryTestSm2Gen();
                            sendMessage("采集SM2密钥对完成");

                            Log.d("AKCEncryptTest", "采集SM2密钥对完成\r\n");

                        }else if (taskIndex == 3){

                            Log.d("AKCEncryptTest", "正在采集SM2加解密\r\n");

                            sendMessage("正在采集SM2加解密");
                            AKCEncryptTest.AKCEncryTestSm2EncryAndDecry();
                            sendMessage("采集SM2加解密完成");

                            Log.d("AKCEncryptTest", "采集SM2加解密完成\r\n");

                        }else if (taskIndex == 4){

                            Log.d("AKCEncryptTest", "正在采集SM2签名/验签\r\n");

                            sendMessage("正在采集SM2签名/验签");
                            AKCEncryptTest.AKCEncryTestSm2Sign();
                            sendMessage("采集SM2签名/验签完成");

                            Log.d("AKCEncryptTest", "采集SM2签名/验签完成\r\n");

                        }else if (taskIndex == 5){

                            Log.d("AKCEncryptTest", "正在采集SM2密钥交换\r\n");

                            sendMessage("正在采集SM2密钥交换");
                            AKCEncryptTest.AKCEncryTestSm2Ecdh();
                            sendMessage("采集SM2密钥交换完成");

                            Log.d("AKCEncryptTest", "采集SM2密钥交换完成\r\n");

                        }else if (taskIndex == 6){

                            Log.d("AKCEncryptTest", "正在采集SM3杂凑\r\n");

                            sendMessage("正在采集SM3杂凑");
                            AKCEncryptTest.AKCEncryTestSm3();
                            sendMessage("采集SM3杂凑完成");

                            Log.d("AKCEncryptTest", "采集SM3杂凑完成\r\n");

                        }else if (taskIndex == 7){

                            Log.d("AKCEncryptTest", "正在采集算法性能\r\n");

                            sendMessage("正在采集算法性能");
                            AKCEncryptTest.AKCEncryTestPerformancea();
                            sendMessage("采集算法性能完成");

                            Log.d("AKCEncryptTest", "采集算法性能完成\r\n");

                        }else{
                            Log.d("AKCEncryptTest", "结束\r\n");
                            sendMessage("结束");
                        }
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }

                }

            }
        }).start();

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
}
