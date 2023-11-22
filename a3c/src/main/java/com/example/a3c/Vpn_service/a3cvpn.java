package com.example.a3c.Vpn_service;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.example.a3c.MainActivity;
import com.example.a3c.function.fileFunc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import static com.example.a3c.function.fileFunc.intToByteLittle;
import static com.example.a3c.function.fileFunc.writeHead;

public class a3cvpn extends VpnService implements Runnable {
    private static final String TAG = "A3C-vpn-service";
    public static final String VPN_TAG = "vpn_tag";  //VPN服务
    public static final int VPN_START = 1;
    public static final int VPN_STOP = -1;
    public static String SP_TAG = "sp_tag";
    public static String SP2_TAG = "sp2_tag";
    public static final String APP_TAG = "app_tag";  //使用VPN的包名
    public static final String APPname_TAG = "app_tag";  //使用VPN的应用名

    //VPN参数配置
    public static final String address_TAG = "address_tag";  //配置服务器地址
    public static final String port_TAG = "port_tag";  //配置服务器端口
    public static final String secret_TAG = "secret_tag";  //配置密钥

    private Thread mThread;  //线程
    private ParcelFileDescriptor mInterface;  //接收文件描述符
    private String mServerAddress;  //服务器地址
    private String mServerPort;  //服务器端口
    private PendingIntent mConfigureIntent;
    public String secret;  //密钥
    private byte[] mSharedSecret;  //密钥比特流形式
    private String mParameters;  //参数
    public File file1;  // pcap文件
    private FileOutputStream f; //文件流
    public String app_choose = null;  //选择包名
    public String app_choose_name = null;  //选择应用名
    public SharedPreferences sp;
    public SharedPreferences sp2;

    public a3cvpn() {
        super();
        Log.d(TAG, "VPN service已创建");
    }

    @Override
    public void onRevoke() {  // 停止VPN
        super.onRevoke();
        Log.d(TAG, "VPN service已停止");
    }

    @Override
    public void onDestroy() {  //销毁service
        super.onDestroy();
        if (mThread != null) {
            mThread.interrupt();
        }
        Log.d(TAG, "VPN service已销毁");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        int tag = intent.getIntExtra(VPN_TAG, VPN_STOP);  //缺省值为STOP
        if (tag == VPN_START) {  //tag为START，开启连接
            //接收用户配置信息
            mServerAddress = intent.getStringExtra(address_TAG);
            mServerPort = intent.getStringExtra(port_TAG);
            secret = intent.getStringExtra(secret_TAG);
            mSharedSecret = secret.getBytes();  // 将密钥化为比特流
            if (mThread != null) {
                mThread.interrupt();
            }
            // 创建线程
            mThread = new Thread((Runnable) this, "A3C-Vpn-Thread");
            mThread.start();
        } else {  // tag为STOP，关闭连接
            try {
                if (mInterface != null) {
                    mInterface.close();  //关闭文件描述符
                    mInterface = null;  //清空文件描述符
                }
            } catch (Exception e) {

            }
            onRevoke();
        }
        return START_STICKY;  //异常kill时，尝试重启service
    }

    @Override
    public synchronized void run() {
        try {
            Log.i(TAG, "Starting");
            InetSocketAddress server = new InetSocketAddress(mServerAddress, Integer.parseInt(mServerPort));  //与服务器地址、端口建立套接字
            //for (int attempt = 0; attempt < 10; ++attempt) { mHandler.sendEmptyMessage(R.string.connecting);
            run(server);
            Thread.sleep(3000);
        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
        } finally {
            try {
                mInterface.close();
            } catch (Exception e) {

            }
            mInterface = null;
            mParameters = null;
            Log.i(TAG, "Exiting");
        }
    }

    private boolean run(InetSocketAddress server) throws Exception {
        DatagramChannel tunnel = null;
        boolean connected = false;
        try {
            tunnel = DatagramChannel.open();  // 建立隧道
            if (!protect(tunnel.socket())) {  // 将应用的隧道套接字保留在系统 VPN 外部，并避免发生循环连接
                throw new IllegalStateException("Cannot protect the tunnel");
            }
            tunnel.connect(server);
            tunnel.configureBlocking(false);  // 将socket设为非阻塞模式
            handshake(tunnel);  // 与服务器握手
            connected = true;  // 连接成功

            // 发送成功消息至主页面，刷新UI
            Message msg = MainActivity.handler.obtainMessage();
            Bundle data = new Bundle();
            data.putInt("connected", 0);
            msg.setData(data);
            msg.sendToTarget();

            // 发送的数据包
            FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
            // 接收的数据包
            FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());
            // 为单个数据包分配缓冲区
            ByteBuffer packet = ByteBuffer.allocate(32767);
            // 追加写入文件流
//            f = new FileOutputStream(file1,true);

            // 转发数据包
            int timer = 0;
            while (true) {
                boolean idle = true;
                // 读取outgoing数据包
                int length = in.read(packet.array());  // length是数据包长度
                if (length > 0) {
//                    // 写入时间戳
//                    long time = System.currentTimeMillis();  // 读取当前时间（毫秒数）
//                    long secondtime0 = time / 1000;  // 时间（秒）
//                    int secondtime = (int)secondtime0;
//                    long minitime0 = time % 1000 * 1000;  // 时间（微秒）
//                    int minitime = (int)minitime0;
//                    byte[] time1 = intToByteLittle(secondtime);  // secondtime转化为比特流
//                    f.write(time1);
//                    byte[] time2 = intToByteLittle(minitime);  // minitime转化为比特流
//                    f.write(time2);
//                    //写入数据包长度
//                    byte[] length0 = intToByteLittle(length);  // length（int）转化为比特流
//                    f.write(length0);
//                    f.write(length0);
                    // 将outgoing数据包写入隧道
                    packet.limit(length);

                    // 此处会抛出java.io.IOException: Operation not permitted，疑似因为UDP发包产生
                    try {
                        tunnel.write(packet);
                    } catch (Exception e) {  // 不抛出error，强制继续运行
                        //ignore
                    }

                     //读取缓冲区中的packet
//                    packet.clear();  // 清空标志位
//                    byte[] mdata = new byte[length];  //将缓冲区内容（ip包）写入比特流mdata
//                    for (int i = 0; i < length; i++) { mdata[i] = packet.get();}
//                    f.write(mdata);  //将mdata写入文件
                    packet.clear();  // 清空标志位
                    idle = false;
                    if (timer < 1) {
                        timer = 1;
                    }
                }
                // 从隧道读取incoming数据包
                length = tunnel.read(packet);
                if (length > 0) {  //忽略以零开头的控制消息
                    if (packet.get(0) != 0) {  //将incoming数据包写入输出流
                        out.write(packet.array(), 0, length);
                    }
//                    //写入时间戳
//                    long time = System.currentTimeMillis();  //读取当前时间（毫秒数）
//                    long secondtime0 = time / 1000;  //时间（秒）
//                    int secondtime = (int)secondtime0;
//                    long minitime0 = time % 1000 * 1000;  //时间（微秒）
//                    int minitime = (int)minitime0;
//                    byte[] time1 = intToByteLittle(secondtime);  //secondtime转化为比特流
//                    f.write(time1);
//                    byte[] time2 = intToByteLittle(minitime);  //minitime转化为比特流
//                    f.write(time2);
//                    //写入数据包长度
//                    byte[] length0 = intToByteLittle(length);  //length（int）转化为比特流
//                    f.write(length0);
//                    f.write(length0);
//                    // 读取缓冲区中的packet
//                    packet.clear();  // 清空标志位
//                    byte[] mdata = new byte[length];
//                    //将缓冲区内容（ip包）写入比特流mdata
//                    for (int i = 0; i < length; i++) { mdata[i] = packet.get(); }
//                    f.write(mdata);  //将mdata写入文件
                    packet.clear();
                    idle = false;
                    if (timer > 0) {
                        timer = 0;
                    }
                }
                if (idle) {
                    Thread.sleep(100);
                    timer += (timer > 0) ? 100 : -100;
                    if (timer < -15000) {  //发送空控制消息
                        packet.put((byte) 0).limit(1);
                        for (int i = 0; i < 3; ++i) {
                            packet.position(0);
                            tunnel.write(packet);
                        }
                        packet.clear();
                        timer = 1;
                    }
                    if (timer > 20000) {
                        throw new IllegalStateException("Timed out");
                    }
                }
            }
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            Log.e("Packet", "Got " + e.toString());
        } finally {
            try {
//                f.close();
                tunnel.close();
            } catch (Exception e) {
                // ignore
            }
        }
        return connected;
    }

    private void handshake(DatagramChannel tunnel) throws Exception {  //握手
        ByteBuffer packet = ByteBuffer.allocate(1024);
        packet.put((byte) 0).put(mSharedSecret).flip();

        for (int i = 0; i < 3; ++i) {  //发送控制消息
            packet.position(0);
            tunnel.write(packet);
        }
        packet.clear();

        for (int i = 0; i < 50; ++i) {
            Thread.sleep(100);

            int length = tunnel.read(packet);
            if (length > 0 && packet.get(0) == 0) {
                configure(new String(packet.array(), 1, length - 1).trim()); //配置接口
                return;
            }
        }
        throw new IllegalStateException("Handshake Timed out");
    }

    private void configure(String parameters) throws Exception {  //配置接口
        // 如果参数相同的旧接口已经存在，则复用
        if (mInterface != null && parameters.equals(mParameters)) {
            Log.i(TAG, "复用已有接口");
            return;
        }
        Builder builder = new Builder();
        // 选择使用VPN的应用
        sp = getSharedPreferences(SP_TAG, Context.MODE_PRIVATE);
        sp2 = getSharedPreferences(SP2_TAG, Context.MODE_PRIVATE);
//        app_choose = sp.getString(APP_TAG,null);  // 接收包名
//        app_choose_name = sp2.getString(APPname_TAG,"all");  // 接收应用名
//        if (app_choose != null) {
//            Log.d("APP-Choose", "选择VPN应用包名：" + app_choose);
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {  // 检查版本
//                builder.addAllowedApplication(app_choose);
//                Log.d("APP-Choose", "开启VPN应用名：" + app_choose_name);
//            } else {
//                Log.d("APP-Choose", "当前版本不支持选择APP");
//            }
//        } else {
//            Log.d("APP-Choose", "开启全局VPN");
//        }

//        // pcap文件
//        file1 = fileFunc.newDownFile(app_choose_name);  // 新建pcap文件
//        writeHead(file1);  // 写入pcap文件头部

        for (String parameter : parameters.split(" ")) {
            String[] fields = parameter.split(",");
            try {
                switch (fields[0].charAt(0)) {
                    case 'm':
                        builder.setMtu(Short.parseShort(fields[1]));
                        break;
                    case 'a':
                        builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                        break;
                    case 'r':
                        builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                        break;
                    case 'd':
                        builder.addDnsServer(fields[1]);
                        break;
                    case 's':
                        builder.addSearchDomain(fields[1]);
                        break;
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Bad parameter: " + parameter);
            }
        }

        try {
            mInterface.close();
        } catch (Exception e) {
            // ignore
        }

        mInterface = builder.setSession("inm")
                .setConfigureIntent(mConfigureIntent)
                .establish();
        mParameters = parameters;
        Log.i(TAG, "New interface: " + parameters);
    }

}
