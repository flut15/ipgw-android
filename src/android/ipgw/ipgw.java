package android.ipgw;

import android.ipgw.R;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
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
    private File shadow_file;
	
    private String USER_ID = "";//用户名
    private String PASSWORD = "";//密码
    private String key = "qwertyui";
    
    // 心跳计时器
    private Timer timer;
    private myTimerTask mytask;
    static final int HEART_BEAT_INTERVAL = 5000;
    static final String[] HEARTBEAT_SERVER = {"162.105.129.27","202.112.7.13"};
    static final int[] HEARTBEAT_SERVER_PORT = {7777,7777};
    
    boolean onConnect;
    
    
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
        shadow_file = new File("/sdcard/ipgw.shadow");
        
        // 载入配置文件和用户名密码
        try{
        	if (!shadow_file.exists()){
        		shadow_file.createNewFile();
        	}
        	else
        		read_shadow();
        }catch (Exception e){
        	//debug.setText(debug.getText() + e.getMessage());
        	Log.e("read shadow", e.getMessage());
        }
        try{
        	if (!conf_file.exists()){
        		conf_file.createNewFile();
        	}
        	else
        		read_conf();
        }catch (Exception e){
        	//debug.setText(debug.getText() + e.getMessage());
        	Log.e("read conf", e.getMessage());
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
    		save_conf();
    		save_shadow();
    	}
    	disconnect();
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
			save_conf();
			save_shadow();
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
    
    // 连接
    private String connect() {
    	String result="";
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
    		if (onConnect == false){
    			Log.i("timerup","Reconnect");
    			connect();
    		}
    		else{
    			if (send_heartbeat() == 0)
    				Log.i("heartbeat", "success");
    			else{
    				Log.i("heartbeat", "failed");
    				//status.setText("连接已断开，正在尝试重新连接...");
    				onConnect = false;
    			}
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
    					result += "包月状态：已包月\n";
    				if (deficit.compareTo("NO") == 0)
    					result += "欠费断网：是\n";
    				else
    					result += "欠费断网：否\n";
    				result += "当前连接："+connections+"个\n";
    				result += "账户余额："+balance+"元\n";
    				result += message;
    	    		onConnect = true;
    			} else {
    				if (parse_param(params, "CONNECTIONS").compareTo("0") == 0)
    					result += "断开全部连接成功";
    				else result += "断开连接成功";
    	    		onConnect = false;
    			}
    		}
    		else{
    			String reason = parse_param(params, "REASON");
    			result += "连接失败\n"+reason;
        		onConnect = false;
    		}
    	}else{
    		result = "未知错误";
    		onConnect = false;
    	}
    	return result;
    	/*
    	String result = "";
    	if (data.indexOf("口令错误") >= 0)
    		result = "密码错误，请重新输入密码";
    	else if (data.indexOf("账户名错误") >= 0)
    		result = "用户名错误，请重新输入用户名";
    	else if (data.indexOf("网络连接成功") >= 0){
    		result = "登陆成功";
    		result += "\n用 户 名："+parse_next_param(data, data.indexOf("用&nbsp;户&nbsp;名："));
    		result += "\n当前地址："+parse_next_param(data, data.indexOf("当前地址"));
    		result += "\n包月状态："+parse_next_param(data, data.indexOf("包月状态"));
    		result += "\n访问范围："+parse_next_param(data, data.indexOf("访问范围"));
    		result += "\n账户余额："+parse_next_param(data, data.indexOf("账户余额"));
    	}
    	else if (data.indexOf("不可在当前计算机访问收费地址") >= 0){
    		result = "连接收费地址失败，请检查是否开通收费网关";
    	}
    	else if (data.indexOf("断开全部连接成功") >= 0){
    		result = "断开全部连接成功";
    	}
    	else if (data.indexOf("网络断开成功") >= 0){
    		result = "网络断开成功";
    	}
    	else
    		result = "未知错误";
    	return result;
    	*/
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
    
    /*
    // 解析下一个参数
    private String parse_next_param(String data, int start){
    	String result = "";
    	int spos = start + 1;
    	int epos;
    	while (data.charAt(spos) != '>'){
    		spos ++;
    	}
    	spos ++;
    	while (data.charAt(spos) != '>')
    		spos ++;
    	spos ++;
    	while (data.charAt(spos) == '<'){
    		spos ++;
    		while (data.charAt(spos) != '>')
    			spos ++;
    		spos ++;
    	}
    	epos = spos;
    	while (data.charAt(epos) != '<'){
    		epos ++;
    	}
    	result = data.substring(spos, epos);
    	return result;
    }
    */
    
    // 获得访问范围
    private int get_range() {
    	if (free.isChecked())
    		return 2;
    	return 1;
    }
    
    // 读取配置文件
    private void read_conf() {
    	try{
    		BufferedReader br = new BufferedReader(new FileReader(conf_file));
    		String conf_string;
    		conf_string = br.readLine();
    		//debug.setText(debug.getText() + "conf:" + conf_string + "\n");
    		if (conf_string.length() >= 4){
    			if (conf_string.charAt(1) == '0'){
    				userid.setText("");
    				passwd.setText("");
    				keep_account.setChecked(false);
    				free.setChecked(true);
    				global.setChecked(false);
    				return;
    			}
    			else
    				keep_account.setChecked(true);
    			if (conf_string.charAt(0) == '0'){
    				free.setChecked(true);
    				global.setChecked(false);
    			} else {
    				free.setChecked(false);
    				global.setChecked(true);
    			}
    			if (conf_string.charAt(2) == '0'){
    				passwd.setText("");
    				save_password.setChecked(false);
    			}
    			else
    				save_password.setChecked(true);
    			if (conf_string.charAt(3) == '0')
    				sign_auto.setChecked(false);
    			else
    				sign_auto.setChecked(true);
    		}
    	}catch (Exception e){
    		//debug.setText(debug.getText() +"\n"+ e.getMessage());
    		Log.e("read conf internal", e.getMessage());
    	}
    }
    
    // 读取账户密码信息
    private void read_shadow() {
       	try{
    		FileInputStream fis = new FileInputStream(shadow_file);
    		byte[] shadow_byte_in = new byte[1024];
    		byte[] shadow_byte;
    		byte[] shadow_raw_byte;
    		int len = fis.read(shadow_byte_in);
    		shadow_byte = new byte[len];
    		int i;
    		for(i = 0; i < len; i ++)
    			shadow_byte[i] = shadow_byte_in[i];
    		
    		shadow_raw_byte = decode(shadow_byte, key.getBytes());
    		
    		String shadow_string = new String(shadow_raw_byte);
    		int pos = shadow_string.indexOf("@#$");
    		String u_string = shadow_string.substring(0,pos);
    		String p_string = shadow_string.substring(pos+3);
    		userid.setText(u_string);
    		passwd.setText(p_string);
    		
    		//debug.setText(debug.getText() + new String(shadow_raw_byte) + "\n");
    	}catch (Exception e){
    		//debug.setText(debug.getText() +"\n"+ e.getMessage());
    		Log.e("read shadow internal", e.getMessage());
    	}
    }
    
    // 保存配置文件
    private void save_conf() {
      	try{
      		String conf_string = "";
      		if (free.isChecked() == true)
      			conf_string += "0";
      		else conf_string += "1";
      		if (keep_account.isChecked() == true)
      			conf_string += "1";
      		else conf_string += "0";
      		if (save_password.isChecked() == true)
      			conf_string += "1";
      		else conf_string += "0";
      		if (sign_auto.isChecked() == true)
      			conf_string += "1";
      		else conf_string += "0";
      		
      		FileOutputStream out = new FileOutputStream(conf_file);
      		out.write(conf_string.getBytes("UTF-8"));
      		out.flush();
      		out.close();
    	}catch (Exception e){
    		//debug.setText(debug.getText() +"\n" + e.getMessage());
    		Log.e("save conf", e.getMessage());
    	}
    }
    
    // 保存账户密码信息
    private void save_shadow() {
      	try{
      		String shadow_raw_string;
      		shadow_raw_string = String.valueOf(userid.getText()) + "@#$" + String.valueOf(passwd.getText());
      		byte[] shadow_byte = encode(shadow_raw_string.getBytes(), key.getBytes());
      		//debug.setText(debug.getText() + new String(shadow_byte) + "\n");
      		
      		FileOutputStream out = new FileOutputStream(shadow_file);
      		out.write(shadow_byte);
      		out.flush();
      		out.close();
    	}catch (Exception e){
    		//debug.setText(debug.getText() +"\n" + e.getMessage());
    		Log.e("save shadow", e.getMessage());
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
    			
    			/*
    			X509Certificate cert_host_1 = chain[0];
    			X509Certificate cert_host_2 = chain[1];
    			CertificateFactory cf = CertificateFactory.getInstance("X.509");
    			//FileInputStream fis = new FileInputStream("ca.cer");
    			InputStream is = getClass().getResourceAsStream("/res/raw/ca.cer");
    			X509Certificate cert_local_1 = (X509Certificate)cf.generateCertificate(is);
    			X509Certificate cert_local_2 = (X509Certificate)cf.generateCertificate(is);
    			X509Certificate cert_local_3 = (X509Certificate)cf.generateCertificate(is);
    			if(cert_host_1.equals(cert_local_1) == false)
    				throw new CertificateException("证书验证失败");
    			cert_host_1.checkValidity();
    			*/
    			
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