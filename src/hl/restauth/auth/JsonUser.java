package hl.restauth.auth;

import java.util.StringTokenizer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class JsonUser extends JSONObject{

	public final static String _USERBASE 		= "userbase";	
	//
	public final static String _UID 			= "uid";
	public final static String _NAME 			= "name";
	public final static String _PASSWORD 		= "password";
	public final static String _AUTHTYPE		= "authtype";
	public final static String _ROLES 			= "roles";
	public final static String _AUTHTOKEN		= "authtoken";
	//
	public final static String _USERAGENT		= "userAgent";
	public final static String _DEVICE			= "device";
	public final static String _CLIENTIP		= "clientIP";
	public final static String _LOGINTIME		= "loginTime";
	
	//
	public void setUserBase(String aUserBase)
	{
		put(_USERBASE, aUserBase);
	}
	
	public String getUserBase()
	{
		return getText(_USERBASE,"-");
	}
	//	
	public void setLoginTime(long aLoginTime)
	{
		setNumber(_LOGINTIME, aLoginTime);
	}
	
	public long getLoginTime()
	{
		return getNumber(_LOGINTIME);
	}
	
	//
	public void setAuthToken(String aAuthToken)
	{
		setText(_AUTHTOKEN, aAuthToken);
	}
	
	public String getAuthToken()
	{
		return getText(_AUTHTOKEN);
	}
		
	//
	public void setUserAgent(String aUserAgent)
	{
		setText(_USERAGENT, aUserAgent);
	}
	
	public String getUserAgent()
	{
		return getText(_USERAGENT,"-");
	}
	//
	public void setDevice(String aDevice)
	{
		setText(_DEVICE, aDevice);
	}
	
	public String getDevice()
	{
		return getText(_DEVICE,"-");
	}
	//
	//
	public void setClientIP(String aClientIP)
	{
		setText(_CLIENTIP, aClientIP);
	}
	
	public String getClientIP()
	{
		return getText(_CLIENTIP,"-");
	}
	//
	
	//
	public void setUserID(String aUserID)
	{
		setText(_UID, aUserID);
	}
	
	public String getUserID()
	{
		return getText(_UID);
	}
	//
	public void setUserName(String aUserName)
	{
		setText(_NAME, aUserName);
	}
	
	public String getUserName()
	{
		return getText(_NAME);	
	}
	//
	public void setUserPassword(String aUserPass)
	{
		setText(_PASSWORD, AuthMgr.obfuscate(aUserPass));
	}
	//
	public String getObfuscatedPassword()
	{
		String sPassword = getText(_PASSWORD);
		
		if(sPassword!=null)
			sPassword = AuthMgr.obfuscate(sPassword);
		
		return sPassword;
	}
	//
	public void setAuthType(String aAuthType)
	{
		setText(_AUTHTYPE, aAuthType);
	}
	
	public String getAuthType()
	{
		return getText(_AUTHTYPE);
	}
	//
	
	public void setUserRoles(String aUserRoles, String sDelim)
	{
		if(aUserRoles==null || aUserRoles.length()==0)
			put(_ROLES, "");
		
		JSONArray jsonArrayRoles = new JSONArray();
		StringTokenizer tk = new StringTokenizer(aUserRoles, sDelim);
		while(tk.hasMoreTokens())
		{
			String sRole = tk.nextToken();
			if(sRole!=null && sRole.length()>0)
				jsonArrayRoles.put(sRole);
		}
		put(_ROLES, jsonArrayRoles);
	}
	
	public void setUserRoles(String[] aUserRole)
	{
		if(aUserRole==null || aUserRole.length==0)
			put(_ROLES, "");
	
		JSONArray jsonArrayRoles = new JSONArray();
		for(String sRole : aUserRole)
		{
			jsonArrayRoles.put(sRole);
		}
		put(_ROLES, jsonArrayRoles);
		
	}
	
	public JSONArray getUserRoles()
	{
		try{
			return (JSONArray) get(_ROLES);
		}
		catch(JSONException ex)
		{
			return null;
		}			
	}
	
	public String getText(String aAttrName, String aDefaultValue)
	{
		String sVal = getText(aAttrName);
		if(sVal==null)
			sVal = aDefaultValue;
		return sVal;
	}
	
	public String getText(String aAttrName)
	{
		String sAttrVal = null;
		if(has(aAttrName))
		{
			sAttrVal = getString(aAttrName);
		}
		return sAttrVal;
	}
	
	public Long getNumber(String aAttrName)
	{
		long lAttrVal = 0;
		if(has(aAttrName))
		{
			lAttrVal = getLong(aAttrName);
		}
		return lAttrVal;
	}
	
	public void setText(String aAttrName, String aAttrVal)
	{
		if(aAttrVal==null)
		{
			remove(aAttrName);
		}
		else
		{
			put(aAttrName, aAttrVal);
		}
	}
	
	public void setNumber(String aAttrName, long aAttrVal)
	{
		if(aAttrVal==0)
		{
			remove(aAttrName);
		}
		else
		{
			put(aAttrName, aAttrVal);
		}
	}
	//	
	
	
    
}
