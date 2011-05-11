package android.ipgw;

import android.ipgw.R;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;

public class ipgw extends Activity {
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        // Listen for button clicks
        Button button_connect = (Button)findViewById(R.id.connect);
        Button button_connect_all = (Button)findViewById(R.id.connect_all);
        Button button_disconnect = (Button)findViewById(R.id.disconnect);
        
        button_connect.setOnClickListener(listener_connect);
        button_connect_all.setOnClickListener(listener_connect_all);
        button_disconnect.setOnClickListener(listener_disconnect);
    }
    private OnClickListener listener_connect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		
    	}
    };
    private OnClickListener listener_connect_all = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		
    	}
    };
    private OnClickListener listener_disconnect = new OnClickListener()
    {
    	public void onClick(View v)
    	{
    		
    	}
    };
}