package android.ipgw;

import android.ipgw.R;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import java.io.*;
import java.net.*;
import java.security.cert.*;
import javax.net.ssl.*;

public class ipgw extends Activity {
    private int port = 5428;
    private String host = "its.pku.edu.cn";
    private String page = "/ipgatewayofpku";
    private String argument = "";
	
    private TextView status;
    private TextView userid;
    private TextView passwd;
	
    private String USER_ID = "";//用户名
    private String PASSWORD = "";//密码
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        // Listen for button clicks
        Button button_connect = (Button)findViewById(R.id.connect);
        Button button_connect_all = (Button)findViewById(R.id.connect_all);
        Button button_disconnect = (Button)findViewById(R.id.disconnect);
        status = (TextView)findViewById(R.id.status);
        userid = (TextView)findViewById(R.id.userid);
        passwd = (TextView)findViewById(R.id.password);
        
        button_connect.setOnClickListener(listener_connect);
        button_connect_all.setOnClickListener(listener_connect_all);
        button_disconnect.setOnClickListener(listener_disconnect);
        
        System.out.print("Program Start.");
    }
    public void onDestroy() {
    	super.onDestroy();
    }
    
    private OnClickListener listener_connect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = connect();
    		status.setText("status : "+USER_ID+" connect.\n"+result);
    	}
    };
    private OnClickListener listener_connect_all = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = connect_all();
    		status.setText("status : "+USER_ID+" connect all.\n"+result);
    	}
    };
    private OnClickListener listener_disconnect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		String result;
    		result = disconnect();
    		status.setText("status : "+USER_ID+" disconnect.\n"+result);
    	}
    };
    // 连接免费地址
    private String connect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range=2&operation=connect";
    		result = https_request();
    	}catch (Exception e){
    		status.setText("error : "+e.getMessage());
    	}
    	return result;
    };
    // 连接收费地址
    private String connect_all() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range=1&operation=connect";
    		result = https_request();
    	} catch (Exception e) {
    		status.setText("error : "+e.getMessage());
    	}
    	return result;
    };
    // 断开连接
    private String disconnect() {
    	String result="";
    	try{
    		USER_ID = String.valueOf(userid.getText());
    		PASSWORD = String.valueOf(passwd.getText());
    		argument = "?uid="+USER_ID+"&password="+PASSWORD+"&timeout=1&range=2&operation=disconnectall";
    		result = https_request();
    	} catch (Exception e) {
    		status.setText("error : "+e.getMessage());
    	}
    	return result;
    };
    // https请求
    private String https_request() throws Exception{
    	String result=""; 
	    // 受访的页面
    	String url = page + argument;
	    // 自定义的管理器
	    X509TrustManager xtm = new MyTrustManager();
	    TrustManager mytm[] = { xtm };
	    // 得到上下文
	    SSLContext ctx = SSLContext.getInstance("SSL");
	    // 初始化
	    ctx.init(null, mytm, null);
	    // 获得工厂
	    SSLSocketFactory factory = ctx.getSocketFactory();
	    // 从工厂获得Socket连接
	    Socket socket = factory.createSocket(host, port);
	    // 剩下的就和普通的Socket操作一样了
	    BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
	    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	    out.write("GET " + url + " HTTP/1.0\n\n");
	    out.flush();
	    // System.out.println("start   work!");
	    String line;
	    StringBuffer sb = new StringBuffer();
	    while ((line = in.readLine()) != null) {
	    	sb.append(line + "\n");
	    }       
	    out.close();
	    in.close();
	    // System.out.println(sb.toString());
	    result = sb.toString();
    	return result;
    }
    // 自定义认证管理类
    class MyTrustManager implements X509TrustManager {
    	MyTrustManager() {
    		// 证书初始化操作
    	}
    	public void checkClientTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// 检查客户端可信任状态
    	}
    	public void checkServerTrusted(X509Certificate chain[], String authType)
    	throws CertificateException {
    		// 检查服务器端可信任状态
    	}
    	// 返回接受的发行商数组
    	public X509Certificate[] getAcceptedIssuers() {
    		return null;
    	}
    }
}