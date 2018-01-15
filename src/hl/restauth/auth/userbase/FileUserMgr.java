package hl.restauth.auth.userbase;

import java.util.Properties;

import org.json.JSONObject;

import hl.restauth.auth.AuthConfig;
import hl.restauth.auth.JsonUser;

public class FileUserMgr implements IUserBase {

	private JSONObject jsonConfig 	= null;
	private String configName		= null;
	
	private AuthConfig authConfig 	= null;
	
	public FileUserMgr(String aFileName, String aConfigName)
	{
		authConfig = AuthConfig.getInstance();
		jsonConfig = new JSONObject();
		jsonConfig.put("filename", aFileName);
		setConfigKey(aConfigName);
	}
	
    public JSONObject getJsonConfig() {
		return jsonConfig;
	}
	
	public JsonUser getUser(String aUserID) {
		if(aUserID==null)
			return null;
		
		JsonUser json = new JsonUser();

		aUserID = aUserID.toLowerCase();
		
		json.setUserID(aUserID);
		
		String sPreFix = getConfigKey()+"."+aUserID+".";
		
		Properties propFileInfo = authConfig.getFileUserProps();
		//Name
		String sName = (String) propFileInfo.getProperty(sPreFix+JsonUser._NAME);
		if(sName!=null)
		{
			json.setUserName(sName);
		}
		else
		{
			return null;
		}
		//
		
		//AuthType
		String sAuthType = (String) propFileInfo.getProperty(sPreFix+JsonUser._AUTHTYPE);
		if(sAuthType!=null)
		{
			json.setAuthType(sAuthType);
		}
		//

		//Roles
		String sRoles = (String) propFileInfo.getProperty(sPreFix+JsonUser._ROLES);
		if(sRoles!=null)
		{
			
			json.setUserRoles(sRoles, AuthConfig._CFG_ROLES_SEPARATOR );
		}
		//
		
		//Password
		String sUserPass = propFileInfo.getProperty(sPreFix+JsonUser._PASSWORD);
		if(sUserPass!=null)
		{
			json.setUserPassword(sUserPass);
		}
		return json;
	}
	
	public String getConfigKey() {
		return this.configName;
	}
	
	public void setConfigKey(String aConfigName) {
		this.configName = aConfigName;
	}

}
