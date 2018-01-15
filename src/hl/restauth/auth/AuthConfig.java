package hl.restauth.auth;

import java.io.IOException;
import java.util.Iterator;
import java.util.Properties;
import java.util.SortedMap;
import java.util.TreeMap;

import org.json.JSONObject;

import hl.common.PropUtil;


public class AuthConfig {
	
	public static String _PROP_FILENAME 			= "auth.properties";
	public final static String _CFG_ROLES_SEPARATOR	= ",";
	
	
	public static String _PROP_KEY_USERBASE = "userbase";
	//
	public static String _PROP_KEY_FILE = "file";
	public static String _PROP_KEY_LDAP = "ldap";
	public static String _PROP_KEY_FACE = "face";
	public static String _PROP_KEY_JDBC = "jdbc";
	public static String _PROP_KEY_AUTH = "auth";

	//
	public static String _LDAP_HOST		= "host";
	public static String _LDAP_PORT		= "port";
	public static String _LDAP_SERVICE_ACCT_DN 	= "service.acct.dn";
	public static String _LDAP_SERVICE_ACCT_PWD = "service.acct.pwd";
	public static String _LDAP_SEARCH_SCOPE		= "ldap.search.scope";
	public static String _LDAP_SEARCH_CRITERIA	= "ldap.search.criteria";	
	public static String _LDAP_USERNAME	= "user.name";
	public static String _LDAP_USERROLES= "user.roles";
	//
	public static String _FACEAPI_COMPARE_URL				= "compare.url";
	public static String _FACEAPI_COMPARE_TARGET 			= "compare.compare-target";	
	public static String _FACEAPI_COMPARE_POST_CONTENTTYPE 	= "compare.post.content-type";
	public static String _FACEAPI_COMPARE_POST_TEMPLATE		= "compare.post.template";
	
	public static String _FACEAPI_COMPARE_THRESHOLD 		= "compare.threshold";
	public static String _FACEAPI_COMPARE_RETRY_HFLIP 		= "compare.retry-hflip";
	public static String _FACEAPI_COMPARE_RESULT_SCORE 		= "Score";
	
	
	public static String _FACEAPI_EXTRACT_URL					= "extract.url";
	public static String _FACEAPI_EXTRACT_POST_CONTENTTYPE		= "extract.post.content-type";
	public static String _FACEAPI_EXTRACT_POST_TEMPLATE			= "extract.post.template";
	public static String _FACEAPI_EXTRACT_POST_RETURN_ATTR		= "extract.post.return.attr";

	//
	public static String _JDBC_CLASSNAME= "classname";
	public static String _JDBC_URL		= "url";
	public static String _JDBC_UID		= "uid";
	public static String _JDBC_PWD		= "pwd";
	public static String _JDBC_DB_TABLE	= "db.table";
	public static String _JDBC_DB_OPT_WHERE_CAUSE 	= "db.opt.where.causes";
	public static String _JDBC_DB_COL_UID			= "db.col.uid";
	public static String _JDBC_DB_COL_NAME			= "db.col.name";
	public static String _JDBC_DB_COL_PASS			= "db.col.password";
	public static String _JDBC_DB_COL_ROLES			= "db.col.roles";
	public static String _JDBC_DB_COL_AUTH			= "db.col.authtype";	
	//
	private Properties propFileInfo = new Properties();
	private Properties propLdapInfo = new Properties();
	private Properties propFaceAuthInfo = new Properties();
	private Properties propJdbcInfo = new Properties();
	
	private Properties propAuthSettingsInfo = new Properties();
	
	private Properties propAll = new Properties();
	//
	private SortedMap<String, String> mapUserbase = new TreeMap<String, String>();
	//
	private static AuthConfig instance = null;
	//
	public static AuthConfig getInstance() 
	{
		if(instance==null)
		{
			instance = new AuthConfig();
		}
		return instance;
	}
	
	public String[] getUserBases()
	{	
		return (String[]) mapUserbase.values().toArray(new String[]{});
	}
	
	public JSONObject getAuthConfig(String aConfigName)
	{
		JSONObject jsonCfg = new JSONObject();
		aConfigName = aConfigName.toLowerCase();
		
		for(Object oKey: propAuthSettingsInfo.keySet())
		{
			String sKey = oKey.toString().substring(aConfigName.length());
			String sVal = propAuthSettingsInfo.getProperty(oKey.toString());
			
			jsonCfg.put(sKey, sVal);
		}
		return jsonCfg;
	}
	
	public JSONObject getLdapConfig(String aConfigName)
	{
		JSONObject jsonCfg = new JSONObject();
		aConfigName = aConfigName.toLowerCase();
		
		jsonCfg.put(_LDAP_HOST, propLdapInfo.getProperty(aConfigName+"."+_LDAP_HOST));
		jsonCfg.put(_LDAP_PORT, propLdapInfo.getProperty(aConfigName+"."+_LDAP_PORT));
		jsonCfg.put(_LDAP_SERVICE_ACCT_DN, propLdapInfo.getProperty(aConfigName+"."+_LDAP_SERVICE_ACCT_DN));
		jsonCfg.put(_LDAP_SERVICE_ACCT_PWD, propLdapInfo.getProperty(aConfigName+"."+_LDAP_SERVICE_ACCT_PWD));
		jsonCfg.put(_LDAP_SEARCH_SCOPE, propLdapInfo.getProperty(aConfigName+"."+_LDAP_SEARCH_SCOPE));
		jsonCfg.put(_LDAP_SEARCH_CRITERIA, propLdapInfo.getProperty(aConfigName+"."+_LDAP_SEARCH_CRITERIA));
		
		jsonCfg.put(_LDAP_USERNAME, propLdapInfo.getProperty(aConfigName+"."+_LDAP_USERNAME));
		jsonCfg.put(_LDAP_USERROLES, propLdapInfo.getProperty(aConfigName+"."+_LDAP_USERROLES));
		return jsonCfg;
	}
	
	public JSONObject getFaceAuthConfig(String aConfigName)
	{
		JSONObject jsonCfg = new JSONObject();
		aConfigName = aConfigName.toLowerCase();
		
		jsonCfg.put(_FACEAPI_COMPARE_URL, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_URL));
		jsonCfg.put(_FACEAPI_COMPARE_TARGET, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_TARGET));
		jsonCfg.put(_FACEAPI_COMPARE_POST_CONTENTTYPE, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_POST_CONTENTTYPE));
		jsonCfg.put(_FACEAPI_COMPARE_POST_TEMPLATE, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_POST_TEMPLATE));
		
		jsonCfg.put(_FACEAPI_COMPARE_THRESHOLD, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_THRESHOLD));
		jsonCfg.put(_FACEAPI_COMPARE_RETRY_HFLIP, "true".equalsIgnoreCase(propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_COMPARE_RETRY_HFLIP)));
		
		//

		jsonCfg.put(_FACEAPI_EXTRACT_URL, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_EXTRACT_URL));
		jsonCfg.put(_FACEAPI_EXTRACT_POST_CONTENTTYPE, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_EXTRACT_POST_CONTENTTYPE));
		jsonCfg.put(_FACEAPI_EXTRACT_POST_TEMPLATE, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_EXTRACT_POST_TEMPLATE));
		jsonCfg.put(_FACEAPI_EXTRACT_POST_RETURN_ATTR, propFaceAuthInfo.getProperty(aConfigName+"."+_FACEAPI_EXTRACT_POST_RETURN_ATTR));
		
		return jsonCfg;
	}
	
	public JSONObject getJdbcConfig(String aConfigName)
	{
		JSONObject jsonCfg = new JSONObject();
		aConfigName = aConfigName.toLowerCase();
		jsonCfg.put(_JDBC_CLASSNAME, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_CLASSNAME));
		jsonCfg.put(_JDBC_URL, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_URL));
		jsonCfg.put(_JDBC_UID, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_UID));
		jsonCfg.put(_JDBC_PWD, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_PWD));
		jsonCfg.put(_JDBC_DB_TABLE, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_TABLE));
		jsonCfg.put(_JDBC_DB_COL_UID, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_COL_UID));
		jsonCfg.put(_JDBC_DB_COL_NAME, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_COL_NAME));
		jsonCfg.put(_JDBC_DB_COL_AUTH, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_COL_AUTH));
		jsonCfg.put(_JDBC_DB_COL_PASS, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_COL_PASS));		
		jsonCfg.put(_JDBC_DB_COL_ROLES, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_COL_ROLES));
		jsonCfg.put(_JDBC_DB_OPT_WHERE_CAUSE, propJdbcInfo.getProperty(aConfigName+"."+_JDBC_DB_OPT_WHERE_CAUSE));
		return jsonCfg;
	}
	
	public Properties getFileUserProps()
	{
		return propFileInfo;
	}
	
	public String getPropValue(String aPropKey)
	{
		return propAll.getProperty(aPropKey);
	}
	
	public void init() throws IOException
	{
		propFileInfo.clear();
		propLdapInfo.clear();
		propJdbcInfo.clear();
		propFaceAuthInfo.clear();
		mapUserbase.clear();
		propAuthSettingsInfo.clear();
		
		propAll = PropUtil.loadProperties(_PROP_FILENAME);
		
		Iterator iter = propAll.keySet().iterator();
		while(iter.hasNext())
		{
			String sOrgkey = (String) iter.next();
			if(sOrgkey!=null)
			{
				String sKey 	= sOrgkey.toLowerCase();
				String sKeyType = sKey;
				String sConfigValue = propAll.getProperty(sOrgkey);
				Properties prop = null;
				
				int iPos = sKey.indexOf(".");
				if(iPos>-1)
				{
					sKeyType = sKey.substring(0, iPos);
					//sKey = sKey.substring(iPos+1);
					//
					//System.out.println("type:"+sKeyType+"   key:"+sKey+"  value:"+sConfigValue);
				}
				//
				
				if(sKeyType.startsWith(_PROP_KEY_USERBASE))
				{
					// Userbase will be sorted according to precedence 
					mapUserbase.put(sKey.toLowerCase(), sConfigValue);
				}
				else
				{
					if(sKeyType.startsWith(_PROP_KEY_FILE))
					{
						prop = propFileInfo;
					}
					//
					else if(sKeyType.startsWith(_PROP_KEY_LDAP))
					{
						prop = propLdapInfo;
					}
					//
					else if(sKeyType.startsWith(_PROP_KEY_JDBC))
					{
						prop = propJdbcInfo;
					}
					//
					else if(sKeyType.startsWith(_PROP_KEY_FACE))
					{
						prop = propFaceAuthInfo;
					}
					//
					else if(sKeyType.startsWith(_PROP_KEY_AUTH))
					{
						prop = propAuthSettingsInfo;
					}
					
					if(prop!=null)
					{
						prop.put(sKey.toLowerCase(), sConfigValue);
					}
				}
				//
			}
		}
	}
	
	
}