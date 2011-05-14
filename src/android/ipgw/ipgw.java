package android.ipgw;

import android.ipgw.R;

import android.app.Activity;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.RadioButton;
import android.widget.TextView;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;
import java.security.cert.*;

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
    private TextView debug;
    private RadioButton free;
    private RadioButton global;
    private CheckBox keep_account;
    private CheckBox sign_auto;
    private File conf_file;
    private File shadow_file;
	
    private String USER_ID = "";//用户名
    private String PASSWORD = "";//密码
    private String key = "qwertyui";
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        // Listen for button clicks
        Button button_connect = (Button)findViewById(R.id.connect);
        Button button_disconnect_all = (Button)findViewById(R.id.disconnect_all);
        Button button_disconnect = (Button)findViewById(R.id.disconnect);
        status = (TextView)findViewById(R.id.status);
        userid = (TextView)findViewById(R.id.userid);
        passwd = (TextView)findViewById(R.id.password);
        debug = (TextView)findViewById(R.id.debug);
        free = (RadioButton)findViewById(R.id.free);
        global = (RadioButton)findViewById(R.id.global);
        keep_account = (CheckBox)findViewById(R.id.keep_account);
        sign_auto = (CheckBox)findViewById(R.id.sign_automatically);
        
        button_connect.setOnClickListener(listener_connect);
        button_disconnect_all.setOnClickListener(listener_disconnect_all);
        button_disconnect.setOnClickListener(listener_disconnect);
        keep_account.setOnCheckedChangeListener(listener_keep_account);
        
        conf_file = new File("/sdcard/ipgw.conf");
        shadow_file = new File("/sdcard/ipgw.shadow");
        try{
        	if (!shadow_file.exists()){
        		shadow_file.createNewFile();
        	}
        	else
        		read_shadow();
        }catch (Exception e){
        	debug.setText(debug.getText() + e.getMessage());
        }
        try{
        	if (!conf_file.exists()){
        		conf_file.createNewFile();
        	}
        	else
        		read_conf();
        }catch (Exception e){
        	debug.setText(debug.getText() + e.getMessage());
        }
        
        // 自动连接
        if (sign_auto.isChecked() == true){
        	String result;
        	result = connect();
        	status.setText(result);
        }
        
        //System.out.print("Program Start.");
    }
    public void onDestroy() {
    	if (keep_account.isChecked() == true){
    		save_conf();
    		save_shadow();
    	}
    	super.onDestroy();
    }
    
    private OnCheckedChangeListener listener_keep_account = new OnCheckedChangeListener()
    {
		@Override
		public void onCheckedChanged(CompoundButton arg0, boolean arg1) {
			save_conf();
			save_shadow();
			if (keep_account.isChecked() == false)
				sign_auto.setChecked(false);
		}
    };
    
    private OnClickListener listener_connect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = connect();
    		status.setText(result);
    	}
    };
    private OnClickListener listener_disconnect_all = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect_all();
    		status.setText(result);
    	}
    };
    private OnClickListener listener_disconnect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect();
    		status.setText(result);
    	}
    };
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
    		result = "连接失败，网络异常或软件已损坏\n" + e.getMessage();
    	}
    	return result;
    };
    // 断开当前连接
    private String disconnect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range="+get_range()+"&operation=disconnectall";
    		result = https_request();
    		result = parse_result(result);
    	} catch (Exception e) {
    		result = "连接失败，网络异常或软件已损坏\n" + e.getMessage();
    	}
    	return result;
    };
    
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
    	conn.connect();
    	
    	BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "GBK"));
    	StringBuffer sb = new StringBuffer();
    	String line;
    	while ((line = br.readLine()) != null)
    		sb.append(line);
    	result = sb.toString();
    	
    	return result;
    }
    
    // 解析结果函数
    private String parse_result(String data){
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
    	else
    		result = "未知错误";
    	return result;
    }
    
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
    		if (conf_string.length() >= 3){
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
    			if (conf_string.charAt(2) == '0')
    				sign_auto.setChecked(false);
    			else
    				sign_auto.setChecked(true);
    			
    		}
    	}catch (Exception e){
    		debug.setText(debug.getText() +"\n"+ e.getMessage());
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
    		debug.setText(debug.getText() +"\n"+ e.getMessage());
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
      		if (sign_auto.isChecked() == true)
      			conf_string += "1";
      		else conf_string += "0";
      		
      		FileOutputStream out = new FileOutputStream(conf_file);
      		out.write(conf_string.getBytes("UTF-8"));
      		out.flush();
      		out.close();
    	}catch (Exception e){
    		debug.setText(debug.getText() +"\n" + e.getMessage());
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
    		debug.setText(debug.getText() +"\n" + e.getMessage());
    	}
    }
    
    // 加密
    public static byte[] encode(byte[] input, byte[] key) 
    	throws Exception 
    {
    	SecretKey   deskey   =   new   javax.crypto.spec.SecretKeySpec(key,   "DES"); 
    	Cipher   c1   =   Cipher.getInstance("DES"); 
    	c1.init(Cipher.ENCRYPT_MODE,   deskey); 
    	byte[]   cipherByte   =   c1.doFinal(input); 
    	return   cipherByte; 
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
    			X509Certificate cert_host = chain[0];
    			CertificateFactory cf = CertificateFactory.getInstance("X.509");
    			//FileInputStream fis = new FileInputStream("ca.cer");
    			InputStream is = getClass().getResourceAsStream("/res/raw/ca.cer");
    			X509Certificate cert_local = (X509Certificate)cf.generateCertificate(is);
    			if(cert_host.equals(cert_local) == false)
    				throw new CertificateException("证书验证失败");
    		}catch (Exception e){
    			debug.setText(debug.getText() + "\n" + e.getMessage());
    			throw new CertificateException("证书读取失败");
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