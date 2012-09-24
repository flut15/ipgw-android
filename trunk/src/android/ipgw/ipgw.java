package android.ipgw;

import android.ipgw.R;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.net.ssl.*;

public class ipgw extends Activity {
    private int port = 5428;
    private String host = "https://its.pku.edu.cn";
    private String page = "/ipgatewayofpku";
    private String argument = "";
	
    private TextView status;
    private TextView userid;
    private TextView passwd;
    //private TextView debug;
    private RadioButton free;
    private RadioButton global;
    private CheckBox keep_account;
    private CheckBox save_password;
    private CheckBox sign_auto;
    private File conf_file;
	
    private String USER_ID = "";//用户名
    private String PASSWORD = "";//密码
    private String key = "qwertyui";
    
    // 心跳计时器
    private Timer timer;
    private myTimerTask mytask;
    static final int HEART_BEAT_INTERVAL = 5000;
    static final int LOSE_CONN_INTERVAL = 20000;
    static final String[] HEARTBEAT_SERVER = {"162.105.129.27","202.112.7.13"};
    static final int[] HEARTBEAT_SERVER_PORT = {7777,7777};
    
    int loseConnCount;
    boolean onConnect;
    
    // 任务栏通知
    NotificationManager nm;
    Notification n;
    String service = Context.NOTIFICATION_SERVICE;
    Intent i;
    PendingIntent contentIntent;
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        // Listen for button clicks
        Button button_connect = (Button)findViewById(R.id.connect);
        Button button_disconnect_all = (Button)findViewById(R.id.disconnect_all);
        Button button_disconnect = (Button)findViewById(R.id.disconnect);
        Button button_exit = (Button)findViewById(R.id.exit);
        
        status = (TextView)findViewById(R.id.status);
        userid = (TextView)findViewById(R.id.userid);
        passwd = (TextView)findViewById(R.id.password);
        //debug = (TextView)findViewById(R.id.debug);
        free = (RadioButton)findViewById(R.id.free);
        global = (RadioButton)findViewById(R.id.global);
        keep_account = (CheckBox)findViewById(R.id.keep_account);
        save_password = (CheckBox)findViewById(R.id.save_password);
        sign_auto = (CheckBox)findViewById(R.id.sign_automatically);
        
        button_connect.setOnClickListener(listener_connect);
        button_disconnect_all.setOnClickListener(listener_disconnect_all);
        button_disconnect.setOnClickListener(listener_disconnect);
        button_exit.setOnClickListener(listener_exit);
        keep_account.setOnCheckedChangeListener(listener_keep_account);
        save_password.setOnCheckedChangeListener(listener_keep_account);
        sign_auto.setOnCheckedChangeListener(listener_keep_account);
        
        conf_file = new File("/sdcard/ipgw.conf");
        loseConnCount = 0;
        
        // 初始化状态栏通知
        nm = (NotificationManager)getSystemService(service);
        n = new Notification(R.drawable.icon, "北京大学校园网IP网关认证客户端(android)", System.currentTimeMillis());
        n.flags = Notification.FLAG_ONGOING_EVENT;
        i = this.getIntent();
        i.setFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        contentIntent = PendingIntent.getActivity(
        		ipgw.this, 
        		R.string.app_name,
        		i, 
        		PendingIntent.FLAG_UPDATE_CURRENT);
        n.setLatestEventInfo(
        		ipgw.this,
        		"北京大学校园网IP网关认证客户端(android)",
        		"当前连接状态：未连接",
        		contentIntent);
        nm.notify(R.string.app_name, n);
        //nm.notify();
        
        // 载入配置文件和用户名密码
        try{
        	if (!conf_file.exists()){
        		conf_file.createNewFile();
        	}
        	else
        		read_config();
        }catch (Exception e){
        	Log.e("read shadow", e.getMessage());
        }
        
        // 自动连接
        if (sign_auto.isChecked() == true){
        	String result;
        	result = connect();
        	status.setText(result);
        }
        
    }
    
    // 程序退出时的处理
    public void onDestroy() {
    	if (keep_account.isChecked() == true){
    		//save_conf();
    		//save_shadow();
    		save_config();
    	}
    	disconnect();
    	nm.cancelAll();
    	super.onDestroy();
    }
    
    // 处理返回键
    public boolean onKeyDown(int keyCode, KeyEvent event) {  
    	PackageManager pm = getPackageManager();
        ResolveInfo homeInfo = pm.resolveActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0);
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            ActivityInfo ai = homeInfo.activityInfo;
            Intent startIntent = new Intent(Intent.ACTION_MAIN);
            startIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            startIntent.setComponent(new ComponentName(ai.packageName, ai.name));
            startActivitySafely(startIntent);
            return true;
        } else
            return super.onKeyDown(keyCode, event);
    }

    // Start main activity safely
    void startActivitySafely(Intent intent) {  
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(this, "Unable to open software.", Toast.LENGTH_SHORT).show();
        } catch (SecurityException e) {
            Toast.makeText(this, "Unable to open software.", Toast.LENGTH_SHORT).show();
            Log.e("Error","Launcher does not have the permission to launch "
            		+ intent
            		+ ". Make sure to create a MAIN intent-filter for the corresponding activity "
            		+ "or use the exported attribute for this activity.",
            		e);
        }
    }
    
    // 勾选“保存账号“时的处理
    private OnCheckedChangeListener listener_keep_account = new OnCheckedChangeListener()
    {
		@Override
		public void onCheckedChanged(CompoundButton arg0, boolean arg1) {
			//save_conf();
			//save_shadow();
			save_config();
			if (keep_account.isChecked() == false){
				save_password.setChecked(false);
				sign_auto.setChecked(false);
			}
			if (save_password.isChecked() == false) {
				sign_auto.setChecked(false);
			}
		}
    };
    
    // 退出键监听器，退出程序
    private OnClickListener listener_exit = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		exit_dialog();
    	}
    };
    
    // 连接键监听器
    private OnClickListener listener_connect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = connect();
    		status.setText(result);
    	}
    };
    
    //断开所有连接键监听器
    private OnClickListener listener_disconnect_all = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect_all();
    		status.setText(result);
    	}
    };
    // 断开连接键监听器
    private OnClickListener listener_disconnect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect();
    		status.setText(result);
    	}
    };
    
    private boolean isWeakPassword(String username, String password){
    	if(password == null)return false;
        else if(password.equals(username)) return true;
    	else if(password.length() < 6) return true;
    	else{
    		char ch = password.charAt(0);
    		int i;
    		for(i=0;i<password.length();i++)if(ch!=password.charAt(0))break;
    		if(i==password.length())return true;
    	}
    	return false;
  	}
    
    // 退出确认对话框
    private void exit_dialog() {
    	AlertDialog.Builder builder = new Builder(ipgw.this);
    	builder.setMessage("退出将断开连接，确认退出吗？");
    	builder.setTitle("提示");
    	builder.setPositiveButton("确认", new DialogInterface.OnClickListener(){
    		public void onClick(DialogInterface dislog, int which){
    			dislog.dismiss();
    			ipgw.this.finish();
    		}
    	});
    	builder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
			}
		});
    	builder.create().show();
    }
    
    static final private String WEAKPASSWORD_PROMPT = "由于部分用户密码简单，近期经常发生黑客盗用北大邮箱发送大量垃圾邮件的情况，使得广大师生无法正常收发邮件，影响工作学习，而且个人信息也有泄露的危险。鉴于您的登录密码过于简单，请您尽快登录http://its.pku.edu.cn修改！";
    
    // 连接
    private String connect() {
    	String result="";
    	Log.i("connect", "connect start");
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range="+get_range()+"&operation=connect";
    		result = https_request();
    		result = parse_result(result);
    	}catch (Exception e){
    		result = "连接失败，网络异常或软件已损坏\n" + e.getMessage();
    		Log.e("connect", e.getMessage());
    		onConnect = false;
    	}
    	//test weak password
    	if(onConnect == true){
    		if(isWeakPassword(USER_ID,PASSWORD))
    		{
    			AlertDialog.Builder ab = new AlertDialog.Builder(this);
    			ab.setMessage(WEAKPASSWORD_PROMPT);
    			ab.setCancelable(false);
    			ab.setPositiveButton("确定", new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
					}
				});
    			AlertDialog ad = ab.create();
    			ad.show();
//    			Toast t = Toast.makeText(this, WEAKPASSWORD_PROMPT, Toast.LENGTH_LONG);
//    			t.setDuration(Toast.LENGTH_LONG);
//    			t.show();
    		}
    	}
    	
    	if (onConnect == true){
    		if (timer != null)
    			timer.cancel();
    		timer = new Timer();
    		mytask = new myTimerTask();
    		timer.schedule(mytask, 0, HEART_BEAT_INTERVAL);
    	}
    	return result;
    };
    // 断开所有连接
    private String disconnect_all() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range=2&operation=disconnectall";
    		result = https_request();
    		result = parse_result(result);
    	} catch (Exception e) {
    		result = "断开所有连接失败，网络异常或软件已损坏\n" + e.getMessage();
    	}
    	//test weak password
    	if(onConnect == false){
    		if(this.isWeakPassword(USER_ID, PASSWORD))
    			Toast.makeText(this, WEAKPASSWORD_PROMPT, Toast.LENGTH_LONG);
    	}
    	
		if (timer != null)
			timer.cancel();
    	return result;
    };
    // 断开当前连接
    private String disconnect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range="+get_range()+"&operation=disconnect";
    		result = https_request();
    		result = parse_result(result);
    	} catch (Exception e) {
    		result = "断开当前连接失败，网络异常或软件已损坏\n" + e.getMessage();
    	}
    	
		if (timer != null)
			timer.cancel();
    	return result;
    };
    
    // 定时器任务，连接心跳服务器
    private class myTimerTask extends TimerTask{
    	public void run() {
    		Log.i("heartbeat","TimerUp, send heartbeat.");
			if (send_heartbeat() == 0){
				Log.i("heartbeat", "success");
				onConnect = true;
	    		//设置状态栏状态
	    		n.icon = R.raw.success;
	            n.setLatestEventInfo(
	            		ipgw.this,
	            		"北京大学校园网IP网关认证客户端(Android)",
	            		"当前连接状态：已连接",
	            		contentIntent);
	            nm.notify(R.string.app_name, n);
	            loseConnCount = 0;
			}
			else{
				Log.i("heartbeat", "failed");
				//status.setText("连接已断开，正在尝试重新连接...");
				if (onConnect == false)
					return;
				loseConnCount ++;
				if (loseConnCount * ipgw.HEART_BEAT_INTERVAL <= ipgw.LOSE_CONN_INTERVAL){
					return;
				}
				onConnect = false;
	    		//设置状态栏状态
	    		n.icon = R.raw.exception;
	            n.setLatestEventInfo(
	            		ipgw.this,
	            		"北京大学校园网IP网关认证客户端(android)",
	            		"当前连接状态：网络异常",
	            		contentIntent);
	            nm.notify(R.string.app_name, n);
			}
    	}
    }
    
    // 向心跳服务器发送心跳并获得心跳
    private int send_heartbeat(){
		String sendMessage = "r[android]";
		String recvMessage;
		int i;
		for (i=0; i<HEARTBEAT_SERVER.length; i++){
			try{
    			InetAddress ia = InetAddress.getByName(HEARTBEAT_SERVER[i]);
    			DatagramSocket socket = new DatagramSocket();
    			socket.setSoTimeout(2000);
    			DatagramPacket dp_send = new DatagramPacket(sendMessage.getBytes(),
    					sendMessage.getBytes().length);
    			socket.connect(ia, HEARTBEAT_SERVER_PORT[i]);
    			DatagramPacket dp_recv = new DatagramPacket(new byte[1024], 1024);
    			socket.send(dp_send);
    			socket.receive(dp_recv);
    			byte[] byte_recv = dp_recv.getData();
    			recvMessage = new String(byte_recv).substring(0, dp_recv.getLength());
    			Log.i("heartbeat "+i,"OK "+recvMessage);
    			return 0;
    		}catch (Exception e){
    			Log.e("heartbeat "+i, e.getMessage());
    		}
    	}
    	return 1;
    }

    // https请求
    private String https_request() throws Exception{
    	
    	String result = "";
    	String url = host + ":" + String.valueOf(port) + page + argument;
    	SSLContext sc = SSLContext.getInstance("TLS");
    	sc.init(null, new TrustManager[]{new MyTrustManager()}, new SecureRandom());
    	HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    	HttpsURLConnection.setDefaultHostnameVerifier(new MyHostnameVerifier());
    	HttpsURLConnection conn = (HttpsURLConnection)new URL(url).openConnection();
    	conn.setDoOutput(true);
    	conn.setDoInput(true);
    	conn.setReadTimeout(5000);
    	conn.connect();
    	
    	BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "GBK"));
    	StringBuffer sb = new StringBuffer();
    	String line;
    	while ((line = br.readLine()) != null)
    		sb.append(line);
    	result = sb.toString();
    	
    	conn.disconnect();
    	
    	return result;
    }
    
    // 解析结果函数
    private String parse_result(String data){
    	String result = "";
    	int start_pos = data.indexOf("<!--IPGWCLIENT_START") + "<!--IPGWCLIENT_START".length();
    	int end_pos = data.indexOf("IPGWCLIENT_END-->");
    	if ( start_pos >= 0 && end_pos > start_pos ){
    		String params = data.substring(start_pos, end_pos);
    		String success = parse_param(params, "SUCCESS");
    		Log.i("params success", success);
    		if (success.compareTo("YES") == 0){
    			if (parse_param(params, "STATE").compareTo("connected") == 0){
    				String username = parse_param(params, "USERNAME");
    				String fixrate = parse_param(params, "FIXRATE");
    				String frdesccn = parse_param(params, "FR_DESC_CN");
    				//String frdescen = parse_param(params, "FR_DESC_EN");
    				String scope = parse_param(params, "SCOPE");
    				String deficit = parse_param(params, "DEFICIT");
    				String connections = parse_param(params, "CONNECTIONS");
    				String balance = parse_param(params, "BALANCE");
    				String ip = parse_param(params, "IP");
    				String message = parse_param(params, "MESSAGE");
    				result += "连接成功\n";
    				result += "用 户 名："+username+"\n";
    				result += "当前IP："+ip+"\n";
    				if (scope.compareTo("domestic") == 0)
    					result += "访问范围：免费地址\n";
    				else
    					result += "访问范围：收费地址\n";
    				if (fixrate.compareTo("NO") == 0)
    					result += "包月状态：未包月\n";
    				else
    					result += "包月状态："+frdesccn+"\n";
    				if (deficit.compareTo("NO") == 0)
    					result += "欠费断网：是\n";
    				else
    					result += "欠费断网：否\n";
    				result += "当前连接："+connections+"个\n";
    				result += "账户余额："+balance+"元\n";
    				result += message;
    	    		onConnect = true;
    	    		//设置状态栏状态
    	    		n.icon = R.raw.success;
    	            n.setLatestEventInfo(
    	            		ipgw.this,
    	            		"北京大学校园网IP网关认证客户端(android)",
    	            		"当前连接状态：已连接",
    	            		contentIntent);
    	            nm.notify(R.string.app_name, n);
    			} else {
    				if (parse_param(params, "CONNECTIONS").compareTo("0") == 0)
    					result += "断开全部连接成功";
    				else result += "断开连接成功";
    	    		onConnect = false;
    	    		//设置状态栏状态
    	    		n.icon = R.raw.failed;
    	            n.setLatestEventInfo(
    	            		ipgw.this,
    	            		"北京大学校园网IP网关认证客户端(android)",
    	            		"当前连接状态：断开连接",
    	            		contentIntent);
    	            nm.notify(R.string.app_name, n);
    			}
    		}
    		else{
    			String reason = parse_param(params, "REASON");
    			result += "连接失败\n"+reason;
        		onConnect = false;
	    		//设置状态栏状态
	    		n.icon = R.raw.failed;
	            n.setLatestEventInfo(
	            		ipgw.this,
	            		"北京大学校园网IP网关认证客户端(android)",
	            		"当前连接状态：连接失败",
	            		contentIntent);
	            nm.notify(R.string.app_name, n);
    		}
    	}else{
    		result = "未知错误";
    		onConnect = false;
    		//设置状态栏状态
    		n.icon = R.raw.failed;
            n.setLatestEventInfo(
            		ipgw.this,
            		"北京大学校园网IP网关认证客户端(android)",
            		"当前连接状态：未知错误",
            		contentIntent);
            nm.notify(R.string.app_name, n);
    	}
    	return result;
    }
    
    private String parse_param(String data, String param){
    	String result = "";
    	int param_pos = data.indexOf(param);
    	if (param_pos < 0)
    		result = "错误的参数";
    	else {
    		int param_start = param_pos + param.length() + 1;
    		int param_end = data.indexOf(" ", param_start);
    		result = data.substring(param_start, param_end);
    	}
    	return result;
    }
    
    // 获得访问范围
    private int get_range() {
    	if (free.isChecked())
    		return 2;
    	return 1;
    }
    
    // 读取配置文件和用户名密码（新）
    private void read_config(){
    	try{
    		FileInputStream fis = new FileInputStream(conf_file);
    		byte[] config_byte_in = new byte[4096];
    		byte[] config_byte;
    		byte[] config_raw_byte;
    		int len = fis.read(config_byte_in);
    		config_byte = new byte[len];
    		int i;
    		for(i = 0; i < len; i ++)
    			config_byte[i] = config_byte_in[i];
    		config_raw_byte = decode(config_byte, key.getBytes());
    		
    		String config_string = new String(config_raw_byte);
    		String is_free = parse_param(config_string, "1-FREE");
    		String is_keep_account = parse_param(config_string, "2-KEEPACCOUNT");
    		String is_save_password = parse_param(config_string, "3-SAVEPASSWORD");
    		String is_sign_auto = parse_param(config_string, "4-SIGNAUTO");
    		String username_string = parse_param(config_string, "5-USERNAME");
    		String password_string = parse_param(config_string, "6-PASSWD");
    		if (is_free.compareTo("NO") == 0){
    			free.setChecked(false);
    			global.setChecked(true);
    		}else{
    			free.setChecked(true);
    			global.setChecked(false);
    		}
    		if (is_keep_account.compareTo("YES") == 0)
    			keep_account.setChecked(true);
    		else keep_account.setChecked(false);
    		if (is_save_password.compareTo("YES") == 0)
    			save_password.setChecked(true);
    		else save_password.setChecked(false);
    		if (is_sign_auto.compareTo("YES") == 0)
    			sign_auto.setChecked(true);
    		else sign_auto.setChecked(false);
    		if (keep_account.isChecked() == false
    				|| username_string.compareTo("错误的参数") == 0)
    			userid.setText("");
    		else userid.setText(username_string);
    		if (save_password.isChecked() == false
    				|| password_string.compareTo("错误的参数") == 0)
    			passwd.setText("");
    		else passwd.setText(password_string);
    		
    		save_config();
    		fis.close();
    	}catch (Exception e){
    		Log.e("Read conf", e.getMessage());
    	}
    }
    
    // 保存配置文件和用户名密码（新）
    private void save_config(){
    	try{
      		String shadow_raw_string = "";
      		if (free.isChecked())
      			shadow_raw_string += "1-FREE=YES ";
      		else
      			shadow_raw_string += "1-FREE=NO ";
      		if (keep_account.isChecked())
      			shadow_raw_string += "2-KEEPACCOUNT=YES ";
      		else
      			shadow_raw_string += "2-KEEPACCOUNT=NO ";
      		if (save_password.isChecked())
      			shadow_raw_string += "3-SAVEPASSWORD=YES ";
      		else
      			shadow_raw_string += "3-SAVEPASSWORD=NO ";
      		if (sign_auto.isChecked())
      			shadow_raw_string += "4-SIGNAUTO=YES ";
      		else
      			shadow_raw_string += "4-SIGNAUTO=NO ";
      		shadow_raw_string += "5-USERNAME="+userid.getText()+" ";
      		shadow_raw_string += "6-PASSWD="+passwd.getText()+"   ";
      		Log.i("Save conf", "USERNAME : "+userid.getText());
      		Log.i("Save conf", "PASSWORD : "+passwd.getText());
      		byte[] shadow_byte = encode(shadow_raw_string.getBytes(), key.getBytes());
      		FileOutputStream out = new FileOutputStream(conf_file);
      		out.write(shadow_byte);
      		out.flush();
      		out.close();
      		Log.i("Save conf", "Save complete");
    	}catch (Exception e){
    		Log.e("Save conf", e.getMessage());
    	}
    }
    
    // 加密
    public static byte[] encode(byte[] input, byte[] key) 
    	throws Exception 
    {
    	SecretKey deskey = new javax.crypto.spec.SecretKeySpec(key, "DES"); 
    	Cipher c1 = Cipher.getInstance("DES"); 
    	c1.init(Cipher.ENCRYPT_MODE, deskey); 
    	byte[] cipherByte = c1.doFinal(input); 
    	return cipherByte; 
    } 
    
    //解密 
    public static byte[] decode(byte[] input, byte[] key) 
        throws Exception 
    { 
    	SecretKey deskey = new javax.crypto.spec.SecretKeySpec(key, "DES"); 
    	Cipher c1 = Cipher.getInstance("DES"); 
		c1.init(Cipher.DECRYPT_MODE,   deskey); 
    	byte[] clearByte = c1.doFinal(input); 
    	return clearByte; 
    } 
    
    // 自定义认证管理类
    class MyTrustManager implements X509TrustManager {
    	MyTrustManager() {
    		// 证书初始化操作
    	}
    	public void checkClientTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// 检查客户端可信任状态
    		//debug.setText(debug.getText()+"A - ");
    	}
    	public void checkServerTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// 检查服务器端可信任状态
    		//debug.setText(debug.getText()+"B - ");
    		try{
    			X509Certificate cert_root = null;
    			InputStream is = getClass().getResourceAsStream("/res/raw/ca.cer");
    			CertificateFactory cf = CertificateFactory.getInstance("X.509");
    			while (is.available() > 0){
    				cert_root = (X509Certificate)cf.generateCertificate(is);
    				byte []b = new byte[50];
    				//is.read(b);
    				Log.i("serverTrusted", "check root"+is.available()+new String(b));
    			}
    			int i;
    			chain[chain.length-1].checkValidity();
    			chain[chain.length-1].verify(cert_root.getPublicKey());
    			for (i = chain.length - 2; i >=0; i --){
    				chain[i].checkValidity();
    				chain[i].verify(chain[i+1].getPublicKey());
    			}
    		}
    		catch (CertificateExpiredException e){
    			Log.e("Certificate expire", e.getMessage());
    			throw new CertificateException("证书到期-"+e.getMessage());
    		}
    		catch (CertificateNotYetValidException e){
    			Log.e("Certificate invalid", e.getMessage());
    			throw new CertificateException("证书失效-"+e.getMessage());
    		}
    		catch (CertificateException e){
    			Log.e("Certificate endoce", e.getMessage());
    			throw new CertificateException("证书编码错误-"+e.getMessage());
    		}
    		catch (NoSuchAlgorithmException e){
    			Log.e("Certificate alg", e.getMessage());
    			throw new CertificateException("不支持的证书算法-"+e.getMessage());
    		}
    		catch (NoSuchProviderException e){
    			Log.e("Certificate provide", e.getMessage());
    			throw new CertificateException("证书提供者错误-"+e.getMessage());
    		}
    		catch (InvalidKeyException e){
    			Log.e("Certificate key", e.getMessage());
    			throw new CertificateException("无效的密钥-"+e.getMessage());
    		}
    		catch (SignatureException e){
    			Log.e("Certificate sig", e.getMessage());
    			throw new CertificateException("证书签名错误-"+e.getMessage());
    		}
    		catch (Exception e){
    			//debug.setText(debug.getText() + "\n" + e.getMessage());
    			Log.e("Certificate", e.getMessage());
    			throw new CertificateException("证书读取失败-"+e.getMessage());
    		}
    	}
    	// 返回接受的发行商数组
    	public X509Certificate[] getAcceptedIssuers() {
    		//debug.setText(debug.getText()+"C - ");
    		return null;
    	}
    }
    private class MyHostnameVerifier implements HostnameVerifier{
    	public boolean verify(String hostname, SSLSession session){
    		//debug.setText(debug.getText() + "\nHOSTNAME:" + hostname);
    		if (hostname.equalsIgnoreCase("its.pku.edu.cn"))
    			return true;
    		return false;
    	}
    }
}