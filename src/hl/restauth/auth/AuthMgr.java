package hl.restauth.auth;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.json.JSONException;
import org.json.JSONObject;

import hl.restauth.auth.userbase.FileUserMgr;
import hl.restauth.auth.userbase.IUserBase;
import hl.restauth.auth.userbase.JDBCMgr;
import hl.restauth.auth.userbase.LDAPMgr;
import hl.common.CryptoUtil;
import hl.common.ImgUtil;

public class AuthMgr {

	public static final String KEY_USERID 			= JsonUser._UID;	
	public static final String KEY_PASSWORD 		= JsonUser._PASSWORD;
	public static final String KEY_AUTHTOKEN 		= JsonUser._AUTHTOKEN;
	
	public static final String HTML_BASE64_HEADER	= ";base64,";
	
	public final static String PARAM_PREFIX		= "${";
	public final static String PARAM_SUFFIX 		= "}";
	public final static String REGEX_PARAM_PREFIX 	= Pattern.quote(PARAM_PREFIX);
	public final static String REGEX_PARAM_SUFFIX 	= Pattern.quote(PARAM_SUFFIX);
	
	public final static String ENCYPT_PREFIX 		= "{obfc}";
	//
	
	private final static String VERSION = "0.3.6";
	//
	

	private AuthConfig authConfig 		= null;
	private AuthSessionMgr authSession 	= AuthSessionMgr.getInstance();
	
	private static List<IUserBase> listUserbase = new ArrayList<IUserBase>();
	private Map<String, Object> mapAuth 		= new HashMap<String, Object>();
	
	public AuthMgr()
	{
		authConfig = AuthConfig.getInstance();
		try {
			reinit();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static String getVersion()
	{
		return VERSION;
	}
	
	public String getConfig(String aConfigKey)
	{
		return authConfig.getPropValue(aConfigKey);
	}
	
	public static String deobfuscate(String aPwd)
    {
    	if(aPwd!=null && aPwd.startsWith(ENCYPT_PREFIX))
		{
    		aPwd = aPwd.substring(ENCYPT_PREFIX.length());
    		aPwd = CryptoUtil.deobfuscate(aPwd);
		}
    	return aPwd;
    }
    
    public static String obfuscate(String aPwd)
    {
    	if(aPwd!=null && aPwd.length()>0)
		{
    		if(aPwd.startsWith(ENCYPT_PREFIX))
    		{
    			return aPwd;
    		}
    		aPwd = ENCYPT_PREFIX 
    				+ CryptoUtil.obfuscate(aPwd);
		}
    	return aPwd;
    }
    
    private LDAPMgr getLDAPmgr(String aLdapConfigName) throws LdapException
    {
    	if(!aLdapConfigName.startsWith(AuthConfig._PROP_KEY_LDAP))
    		throw new LdapException("Invalid Ldap config ! - "+aLdapConfigName);
    	
    	LDAPMgr ldapMgr = (LDAPMgr) mapAuth.get(aLdapConfigName);
		if(ldapMgr==null)
		{
			JSONObject jsonldap = authConfig.getLdapConfig(aLdapConfigName);
			
			//
			try{
				ldapMgr = new LDAPMgr(
						jsonldap.getString(AuthConfig._LDAP_HOST),
						jsonldap.getInt(AuthConfig._LDAP_PORT));
				
				ldapMgr.setJsonConfig(jsonldap);
				ldapMgr.setConfigKey(aLdapConfigName);
			}catch(org.json.JSONException ex)
			{ 
				return null; 
			}
			//
			try{
				ldapMgr.setSearch_scope(
					jsonldap.getString(AuthConfig._LDAP_SEARCH_SCOPE));
			}catch(org.json.JSONException ex){}
			//
			try{
				ldapMgr.setSearch_criteria(
					jsonldap.getString(AuthConfig._LDAP_SEARCH_CRITERIA));
			}catch(org.json.JSONException ex){}
			//
			String sServiceAcctDN = jsonldap.getString(AuthConfig._LDAP_SERVICE_ACCT_DN);
			String sServiceAcctPass = deobfuscate(jsonldap.getString(AuthConfig._LDAP_SERVICE_ACCT_PWD));
			ldapMgr.bindServiceAcct(sServiceAcctDN,	sServiceAcctPass);
			
			mapAuth.put(aLdapConfigName, ldapMgr);
		}    	
		
		return ldapMgr;
    }
    
    private JDBCMgr getJDBCmgr(String aJdbcConfigName) throws SQLException 
    {
    	if(!aJdbcConfigName.startsWith(AuthConfig._PROP_KEY_JDBC))
    		throw new SQLException("Invalid JDBC config ! - "+aJdbcConfigName);
    	
    	JDBCMgr jdbcMgr = (JDBCMgr) mapAuth.get(aJdbcConfigName);
		if(jdbcMgr==null)
		{
			JSONObject jsonJdbc = authConfig.getJdbcConfig(aJdbcConfigName);
			try{
				try {
					jdbcMgr = new JDBCMgr(
							jsonJdbc.getString(AuthConfig._JDBC_CLASSNAME)
							, jsonJdbc.getString(AuthConfig._JDBC_URL)
							, jsonJdbc.getString(AuthConfig._JDBC_UID)
							, jsonJdbc.getString(AuthConfig._JDBC_PWD)
							);
				} catch (Exception e) {
					return null;
				}
			}catch(JSONException ex){}
			
			if(jdbcMgr!=null)
			{
				jdbcMgr.setJsonConfig(jsonJdbc);
				jdbcMgr.setConfigKey(aJdbcConfigName);
				
				StringBuffer sb = new StringBuffer();
				sb.append(" SELECT * FROM ").append(jsonJdbc.getString(AuthConfig._JDBC_DB_TABLE));
				String sWhereCause = null;				
				try{
					sWhereCause = jsonJdbc.getString(AuthConfig._JDBC_DB_OPT_WHERE_CAUSE);
				}catch(JSONException ex){}
				if(sWhereCause==null)
					sWhereCause = "1=1";
				sb.append(" WHERE ").append(sWhereCause);
				sb.append(" AND ").append(jsonJdbc.getString(AuthConfig._JDBC_UID)).append(" = ? ");
				
				jdbcMgr.addSQLtemplates("AuthMgr.getUserInfo", sb.toString());
				
				mapAuth.put(aJdbcConfigName, jdbcMgr);
			}
		}    	
		
		return jdbcMgr;
    }
    
    public static JsonUser getUser(String aUserID)
    {
    	if(aUserID==null)
    		return null;
    	
    	JsonUser jsonUser = null;
    	for(IUserBase ub: listUserbase)
    	{
    		try {
				jsonUser = ub.getUser(aUserID);
				if(jsonUser!=null)
	    		{
	    			jsonUser.setUserBase(ub.getConfigKey());
	    			break;
	    		}
			} catch (Exception e) {
				// TODO
				jsonUser = null;
				e.printStackTrace();
			}
    	}
    	return jsonUser;
    }
    
    public JsonUser isAuthenticated(String aUserID, String aAuthToken)
    {
    	JsonUser jsonUser = null;
    	if(authSession.isValid(aUserID, aAuthToken))
    	{
    		jsonUser = getUser(aUserID);
    	}
    	return removeSensitiveInfo(jsonUser);
    }
  
    public boolean invalidateAuthToken(String aAuthToken)
    {
    	return authSession.invalidate(aAuthToken);
    }
    
    public boolean logout(String aUserID)
    {
    	return authSession.logoutUser(getUser(aUserID));
    }
    
    public JsonUser authenticate(String aUserID, String aUserAttemptPwd) throws LdapException, SQLException, IOException
    {
    	JsonUser jsonUserLogin = new JsonUser();
    	jsonUserLogin.setUserID(aUserID);
    	jsonUserLogin.setUserPassword(aUserAttemptPwd);
    	return authenticate(jsonUserLogin);
    }
    
    public JsonUser authenticate(JsonUser aJsonUserLogin) throws LdapException, SQLException, IOException
    {
    	if(!aJsonUserLogin.has(KEY_USERID)|| !aJsonUserLogin.has(KEY_PASSWORD))
    		return null;
    	
    	String sUserID 			= aJsonUserLogin.getString(KEY_USERID);
    	String sUserAttempPwd 	= aJsonUserLogin.getString(KEY_PASSWORD);
    	
    	JsonUser jsonUser = getUser(sUserID);
    	
    	if(jsonUser!=null)
    	{   
    		for(String sKey : aJsonUserLogin.keySet())
    		{
    			if(KEY_PASSWORD.equals(sKey))
    				continue;
    			
    			if(!jsonUser.has(sKey))
    			{
    				jsonUser.put(sKey, aJsonUserLogin.get(sKey));
    			}
    		}
    		
    		if(jsonUser.getObfuscatedPassword()!=null)
    		{
    			String sObfuscatedAttemptPwd = obfuscate(sUserAttempPwd);
    			if(!sObfuscatedAttemptPwd.equals(jsonUser.getObfuscatedPassword()))
    				return null;
    		}
    		else
    		{
	    		String sAuthType = jsonUser.getAuthType();
	    		if(sAuthType!=null)
	    		{
	    			if(sAuthType.startsWith(AuthConfig._PROP_KEY_LDAP))
	    			{
		    			LDAPMgr ldap = getLDAPmgr(jsonUser.getAuthType());
		    			if(ldap.testAuth(sUserID, deobfuscate(sUserAttempPwd))==null)
		    			{
		    				return null;
		    			}
	    			}
	    			else if(sAuthType.startsWith(AuthConfig._PROP_KEY_FACE))
	    			{
	    				
	    				JSONObject jsonFaceAuthConfig = authConfig.getFaceAuthConfig(jsonUser.getAuthType());
	    				jsonUser = new FaceAuth().faceMatching(jsonUser, sUserAttempPwd, jsonFaceAuthConfig);	    				
	    			}
	    		}
    		}
    	}
    	
    	return removeSensitiveInfo(appendAuthToken(jsonUser));
    }
    
    private JsonUser appendAuthToken(JsonUser aJsonUser)
    {
    	if(aJsonUser!=null)
    	{
    		aJsonUser.setLoginTime(System.currentTimeMillis());
    		aJsonUser = authSession.register(aJsonUser);
    	}
    	
    	return aJsonUser;
    }
    
    private JsonUser removeSensitiveInfo(JsonUser aJsonUser)
    {
    	if(aJsonUser!=null)
    	{
    		if(aJsonUser.has(KEY_PASSWORD))
    			aJsonUser.remove(KEY_PASSWORD);
    	}
    	
    	return aJsonUser;
    }
    
    public static String RegexEscapedParam(final String aString)
    {
    	return REGEX_PARAM_PREFIX+aString+REGEX_PARAM_SUFFIX;
    }
    
    public void cleanUp()
    {
    	for(String sKey : mapAuth.keySet())
    	{
    		Object objAuth = mapAuth.get(sKey);
    		if(objAuth instanceof LDAPMgr)
    		{
    			try {
					((LDAPMgr)objAuth).unbindServiceAcct();
				} catch (LdapException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
    		}
    	}
    }
    
    public void reinit() throws Exception
    {
    	cleanUp();
    	authConfig.init();
    	listUserbase.clear();
    	
    	for(String authConfigKey : authConfig.getUserBases())
    	{
    		if(authConfigKey.startsWith(AuthConfig._PROP_KEY_LDAP))
    		{
    			LDAPMgr ldap = getLDAPmgr(authConfigKey);
    			if(ldap!=null)
    			{
    				listUserbase.add(ldap);
    			}
    		} 
    		else if(authConfigKey.startsWith(AuthConfig._PROP_KEY_JDBC))
    		{
    			JDBCMgr jdbc = getJDBCmgr(authConfigKey);
    			if(jdbc!=null)
    			{
    				listUserbase.add(jdbc);
    			}
    		}
    		else if(authConfigKey.startsWith(AuthConfig._PROP_KEY_FILE))
    		{
    			FileUserMgr file = new FileUserMgr(AuthConfig._PROP_FILENAME, authConfigKey);
    			if(file!=null)
    			{
    				listUserbase.add(file);
    			}
    		}
    		
    	}
    	
    }
    
    public static void main(String args[]) throws Exception 
    {    	

       	String testUid = null;
    	JSONObject jsonLogin = null;
    	AuthMgr authMgr = new AuthMgr();

    	testUid = "poweruser";
    	jsonLogin = authMgr.authenticate(testUid, "p0weruser");
    	System.out.println("[prop] "+testUid+" : "+(jsonLogin!=null?jsonLogin.toString():"login failed!"));
    	
    	jsonLogin = authMgr.authenticate(testUid, "p0weruser");
    	System.out.println("[prop] 2nd login - "+testUid+" : "+(jsonLogin!=null?jsonLogin.toString():"login failed!"));

    	testUid = "nls_atlassian1"; //this is not under NLS so test will fail
    	jsonLogin = authMgr.authenticate(testUid, "{obfc}NVNlZWJjZnU2cjZpMXQyeWFAODE1MmEz");
    	System.out.println("[ldap] "+testUid+" : "+(jsonLogin!=null?jsonLogin.toString():"login failed!"));

    	String image = ImgUtil.getBase64FromFile(".\\test\\onghuilam.base64");
    	testUid = "onghuilam";
    	jsonLogin = authMgr.authenticate(testUid, image);
    	System.out.println("[face] "+testUid+" : "+(jsonLogin!=null?jsonLogin.toString():"login failed!"));

    	
    	
    	authMgr.cleanUp();
    }
}
