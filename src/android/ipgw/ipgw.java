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
import java.security.SecureRandom;
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
	
    private String USER_ID = "";//�û���
    private String PASSWORD = "";//����
    private String key = "qwertyui";
    
    // ������ʱ��
    private Timer timer;
    private myTimerTask mytask;
    static final int HEART_BEAT_INTERVAL = 30000;
    static final String[] HEARTBEAT_SERVER = {"162.105.129.27","202.112.7.13"};
    static final int[] HEARTBEAT_SERVER_PORT = {7777,7777};
    
    
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
        
        mytask = new myTimerTask();
        
        // ���������ļ����û�������
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
        
        // �Զ�����
        if (sign_auto.isChecked() == true){
        	String result;
        	result = connect();
        	status.setText(result);
        }
        
    }
    
    // �����˳�ʱ�Ĵ���
    public void onDestroy() {
    	if (keep_account.isChecked() == true){
    		save_conf();
    		save_shadow();
    	}
    	disconnect();
    	super.onDestroy();
    }
    
    // �����ؼ�
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
    
    // ��ѡ�������˺š�ʱ�Ĵ���
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
		}
    };
    
    // ���Ӽ�������
    private OnClickListener listener_connect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = connect();
    		status.setText(result);
    	}
    };
    
    // �˳������������˳�����
    private OnClickListener listener_exit = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		exit_dialog();
    	}
    };
    
    //�Ͽ��������Ӽ�������
    private OnClickListener listener_disconnect_all = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect_all();
    		status.setText(result);
    	}
    };
    // �Ͽ����Ӽ�������
    private OnClickListener listener_disconnect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect();
    		status.setText(result);
    	}
    };
    
    // �˳�ȷ�϶Ի���
    private void exit_dialog() {
    	AlertDialog.Builder builder = new Builder(ipgw.this);
    	builder.setMessage("�˳����Ͽ����ӣ�ȷ���˳���");
    	builder.setTitle("��ʾ");
    	builder.setPositiveButton("ȷ��", new DialogInterface.OnClickListener(){
    		public void onClick(DialogInterface dislog, int which){
    			dislog.dismiss();
    			ipgw.this.finish();
    		}
    	});
    	builder.setNegativeButton("ȡ��", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
			}
		});
    	builder.create().show();
    }
    
    // ����
    private String connect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range="+get_range()+"&operation=connect";
    		result = https_request();
    		result = parse_result(result);
    	}catch (Exception e){
    		result = "����ʧ�ܣ������쳣���������\n" + e.getMessage();
    	}
		if (timer != null)
			timer.cancel();
		timer = new Timer();
		timer.schedule(mytask, 0, HEART_BEAT_INTERVAL);
    	return result;
    };
    // �Ͽ���������
    private String disconnect_all() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range=2&operation=disconnectall";
    		result = https_request();
    		result = parse_result(result);
    	} catch (Exception e) {
    		result = "�Ͽ���������ʧ�ܣ������쳣���������\n" + e.getMessage();
    	}
		if (timer != null)
			timer.cancel();
    	return result;
    };
    // �Ͽ���ǰ����
    private String disconnect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range="+get_range()+"&operation=disconnect";
    		result = https_request();
    		result = parse_result(result);
    	} catch (Exception e) {
    		result = "�Ͽ���ǰ����ʧ�ܣ������쳣���������\n" + e.getMessage();
    	}
		if (timer != null)
			timer.cancel();
    	return result;
    };
    
    // ��ʱ��������������������
    private class myTimerTask extends TimerTask{
    	public void run() {
    		Log.i("heartbeat","TimerUp, send heartbeat.");
    		if (send_heartbeat() == 0)
    			Log.i("heartbeat", "success");
    		else
    			Log.i("heartbeat", "failed");
    	}
    }
    
    // �����������������������������
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
    
    // https����
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
    
    // �����������
    private String parse_result(String data){
    	String result = "";
    	if (data.indexOf("�������") >= 0)
    		result = "���������������������";
    	else if (data.indexOf("�˻�������") >= 0)
    		result = "�û������������������û���";
    	else if (data.indexOf("�������ӳɹ�") >= 0){
    		result = "��½�ɹ�";
    		result += "\n�� �� ����"+parse_next_param(data, data.indexOf("��&nbsp;��&nbsp;����"));
    		result += "\n��ǰ��ַ��"+parse_next_param(data, data.indexOf("��ǰ��ַ"));
    		result += "\n����״̬��"+parse_next_param(data, data.indexOf("����״̬"));
    		result += "\n���ʷ�Χ��"+parse_next_param(data, data.indexOf("���ʷ�Χ"));
    		result += "\n�˻���"+parse_next_param(data, data.indexOf("�˻����"));
    	}
    	else if (data.indexOf("�����ڵ�ǰ����������շѵ�ַ") >= 0){
    		result = "�����շѵ�ַʧ�ܣ������Ƿ�ͨ�շ�����";
    	}
    	else if (data.indexOf("�Ͽ�ȫ�����ӳɹ�") >= 0){
    		result = "�Ͽ�ȫ�����ӳɹ�";
    	}
    	else if (data.indexOf("����Ͽ��ɹ�") >= 0){
    		result = "����Ͽ��ɹ�";
    	}
    	else
    		result = "δ֪����";
    	return result;
    }
    
    // ������һ������
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
    
    // ��÷��ʷ�Χ
    private int get_range() {
    	if (free.isChecked())
    		return 2;
    	return 1;
    }
    
    // ��ȡ�����ļ�
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
    			if (conf_string.charAt(3) == '0')
    				sign_auto.setChecked(false);
    			else
    				sign_auto.setChecked(true);
    			if (conf_string.charAt(2) == '0'){
    				passwd.setText("");
    				save_password.setChecked(false);
    			}
    			else
    				save_password.setChecked(true);
    		}
    	}catch (Exception e){
    		//debug.setText(debug.getText() +"\n"+ e.getMessage());
    		Log.e("read conf internal", e.getMessage());
    	}
    }
    
    // ��ȡ�˻�������Ϣ
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
    
    // ���������ļ�
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
    
    // �����˻�������Ϣ
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
    
    // ����
    public static byte[] encode(byte[] input, byte[] key) 
    	throws Exception 
    {
    	SecretKey   deskey   =   new   javax.crypto.spec.SecretKeySpec(key,   "DES"); 
    	Cipher   c1   =   Cipher.getInstance("DES"); 
    	c1.init(Cipher.ENCRYPT_MODE,   deskey); 
    	byte[]   cipherByte   =   c1.doFinal(input); 
    	return   cipherByte; 
    } 
    
    //���� 
    public static byte[] decode(byte[] input, byte[] key) 
        throws Exception 
    { 
    	SecretKey deskey = new javax.crypto.spec.SecretKeySpec(key, "DES"); 
    	Cipher c1 = Cipher.getInstance("DES"); 
		c1.init(Cipher.DECRYPT_MODE,   deskey); 
    	byte[] clearByte = c1.doFinal(input); 
    	return clearByte; 
    } 
    
    // �Զ�����֤������
    class MyTrustManager implements X509TrustManager {
    	MyTrustManager() {
    		// ֤���ʼ������
    	}
    	public void checkClientTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// ���ͻ��˿�����״̬
    		//debug.setText(debug.getText()+"A - ");
    	}
    	public void checkServerTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// ���������˿�����״̬
    		//debug.setText(debug.getText()+"B - ");
    		try{
    			X509Certificate cert_host = chain[0];
    			CertificateFactory cf = CertificateFactory.getInstance("X.509");
    			//FileInputStream fis = new FileInputStream("ca.cer");
    			InputStream is = getClass().getResourceAsStream("/res/raw/ca.cer");
    			X509Certificate cert_local = (X509Certificate)cf.generateCertificate(is);
    			if(cert_host.equals(cert_local) == false)
    				throw new CertificateException("֤����֤ʧ��");
    		}catch (Exception e){
    			//debug.setText(debug.getText() + "\n" + e.getMessage());
    			Log.e("Certificate", e.getMessage());
    			throw new CertificateException("֤���ȡʧ��");
    		}
    	}
    	// ���ؽ��ܵķ���������
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