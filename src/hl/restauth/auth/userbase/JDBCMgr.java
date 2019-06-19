package hl.restauth.auth.userbase;

import java.sql.SQLException;
import java.util.List;

import org.json.JSONObject;

import hl.restauth.auth.AuthConfig;
import hl.restauth.auth.JsonUser;
import hl.common.db.DBMgr;

public class JDBCMgr extends DBMgr implements IUserBase {

    private JSONObject jsonConfig	= null;
    private String config_name		= null;
	private final static String SQL_TEMPLATE_NAME	= "AuthMgr.getUserInfo";
	

	public JDBCMgr(String aClassName, String aDBUrl, String aDBUid, String aDBPwd)
			throws InstantiationException, IllegalAccessException, ClassNotFoundException, SQLException {
		super(aClassName, aDBUrl, aDBUid, aDBPwd);
	}

	//
    public JSONObject getJsonConfig() {
		return jsonConfig;
	}

	public void setJsonConfig(JSONObject jsonConfig) {
		this.jsonConfig = jsonConfig;
	}
	
	public String getConfigKey() {
		return this.config_name;
	}
	
	public void setConfigKey(String aConfigName) {
		this.config_name = aConfigName;
	}
	
	public JsonUser getUser(String aUserID)
	{
		JsonUser jsonUser = null;
		try{
			List<String> listUsers = 
					executeTemplateQueryToJson(SQL_TEMPLATE_NAME, new Object[]{aUserID});
			
			if(listUsers.size()==0)
			{
				return null;
			}
			else
			{
				String sJson = listUsers.get(0);
				
				sJson = sJson.replaceAll(
						jsonConfig.getString(AuthConfig._JDBC_DB_COL_UID), JsonUser._UID);
				
				sJson = sJson.replaceAll(
						jsonConfig.getString(AuthConfig._JDBC_DB_COL_NAME), JsonUser._NAME);
				
				if(jsonConfig.has(AuthConfig._JDBC_DB_COL_PASS))
				{
					sJson = sJson.replaceAll(
							jsonConfig.getString(AuthConfig._JDBC_DB_COL_PASS), JsonUser._PASSWORD);
				}				
				if(jsonConfig.has(AuthConfig._JDBC_DB_COL_ROLES))
				{
					sJson = sJson.replaceAll(
							jsonConfig.getString(AuthConfig._JDBC_DB_COL_ROLES), JsonUser._ROLES);
				}				
				if(jsonConfig.has(AuthConfig._JDBC_DB_COL_AUTH))
				{
					sJson = sJson.replaceAll(
							jsonConfig.getString(AuthConfig._JDBC_DB_COL_AUTH), JsonUser._AUTHTYPE);
				}
				JSONObject json = new JSONObject(sJson);
				
				if(json.has(JsonUser._UID))
				{
					if(aUserID.equals(json.getString(JsonUser._UID)))
					{
						jsonUser = new JsonUser();
						jsonUser.setUserID(aUserID);
					}
				}
				
				String sName 	= json.getString(JsonUser._NAME);
				String sRoles 	= json.getString(JsonUser._ROLES);
				String sPass 	= json.getString(JsonUser._PASSWORD);
				
				if(sName!=null)
					jsonUser.setUserName(sName);

				if(sRoles!=null)
					jsonUser.setUserRoles(sRoles, AuthConfig._CFG_ROLES_SEPARATOR);
				
				if(sPass!=null)
					jsonUser.setUserPassword(sPass);
				
			}
		}catch(SQLException ex)
		{
			//TODO
			ex.printStackTrace();
			jsonUser = null;
		}	
		
		return jsonUser;
	}
}
