package hl.restauth.auth.userbase;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.json.JSONObject;

import hl.restauth.auth.AuthConfig;
import hl.restauth.auth.AuthMgr;
import hl.restauth.auth.JsonUser;

public class LDAPMgr implements IUserBase {

	private final static String UID_VARNAME 	= "_uid_";
	
	private final static String LDAP_DN 		= "distinguishedName";
	
	private LdapConnection ldap_service = null;
	private LdapConnection ldap_test 	= null;
	
	private String search_basedn 	= null;
	private String search_scope 	= "DC";
    private String search_criteria 	= "(sAMAccountName="+UID_VARNAME+")";
    
    private JSONObject jsonConfig	= null;
    private String configName		= null;

	public LDAPMgr (String aLDAPServer, int aLDAPPort)
    {
    	if(aLDAPPort<=0)
    		aLDAPPort = 389;
    	
    	this.ldap_service = new LdapNetworkConnection( aLDAPServer, aLDAPPort );
		this.ldap_test = new LdapNetworkConnection( aLDAPServer, aLDAPPort );
    }
    
    ////
    public JSONObject getJsonConfig() {
		return jsonConfig;
	}

	public void setJsonConfig(JSONObject jsonConfig) {
		this.jsonConfig = jsonConfig;
	}

	public String getSearch_scope() {
		return search_scope;
	}

	public void setSearch_scope(String search_scope) {
		if(search_scope==null)
			search_scope = "DC";
		this.search_scope = search_scope;
	}

	public String getSearch_criteria() {
		return search_criteria;
	}

	public void setSearch_criteria(String search_criteria) {
		if(search_criteria==null)
			search_criteria = "(sAMAccountName="+UID_VARNAME+")";
		this.search_criteria = search_criteria;
	}
	////
	
    public void bindServiceAcct(String aServiceDN, String aServicePwd) throws LdapException
    {
    	this.ldap_service.bind(aServiceDN, aServicePwd);
    	
    	if(this.search_basedn==null)
    	{
    		int iSearchNode = aServiceDN.toUpperCase().indexOf(this.search_scope+"=");
    		if(iSearchNode>-1)
    		{
    			this.search_basedn = aServiceDN.substring(iSearchNode);
    		}
    	}
    }
    
    public void unbindServiceAcct() throws LdapException 
    {
    	this.ldap_service.unBind();
    }
    
    
    public void setSearchBaseDN(String aSearchBaseDN)
    {
    	this.search_basedn = aSearchBaseDN;
    }
    
    public Entry search(String aSearchValue) throws LdapException, CursorException
    {
    	return search(null, null, aSearchValue);
    }
    
    public Entry search(String aSearchBaseDN, String aSearchAttr, String aSearchValue) throws LdapException, CursorException
    {
    	Entry e = null;
    	
    	if(aSearchBaseDN==null)
    		aSearchBaseDN = this.search_basedn;

    	if(aSearchAttr==null)
    		aSearchAttr = this.search_criteria;
    	
    	aSearchAttr = aSearchAttr.replaceAll(UID_VARNAME, aSearchValue);
    	
    	EntryCursor cursor = this.ldap_service.search( 
    			aSearchBaseDN, 
    			aSearchAttr, 
    			SearchScope.SUBTREE );
    	if(cursor.next())
    	{
    		e = cursor.get();
    	}
    	return e;
    }
    
    public Entry testAuth(String aTestUid, String aTestPwd)
    {
    	return testAuth(this.search_basedn, aTestUid, aTestPwd);
    }
    
    public Entry testAuth(String aTestBaseDN, String aTestUid, String aTestPwd)
    {
    	Entry entryUser=null;
    	try {
    		
    		if(aTestPwd==null)
    			return null;
    		
			try {
				entryUser = search(aTestBaseDN, null, aTestUid);
			} catch (CursorException e) {
				e.printStackTrace();
			}
    		
    		if(entryUser!=null)
    		{
    			if(!testAuth(entryUser, aTestPwd))
    			{
    				return null;
    			}
    		}
			
		} catch (LdapException e) {
			
		} finally
    	{
			try {
				if(this.ldap_test.isAuthenticated())
					this.ldap_test.unBind();
			} catch (LdapException e) {
				e.printStackTrace();
			}
    	}
    	
    	return entryUser;
    }
    
    public boolean testAuth(Entry aUserEntry, String aTestPwd)
    {
		if(aUserEntry!=null)
		{
			Attribute attrUserDN = aUserEntry.get(LDAP_DN);
			try {
				this.ldap_test.bind(attrUserDN.getString(), aTestPwd);
				return true;
			} catch (LdapException e) {
				// TODO
				e.printStackTrace();
			}
		}
		return false;
    }
    
    public JsonUser getUser(String aUserID) throws LdapException, CursorException
    {    	
    	Entry entryUser = search(aUserID);
		if(entryUser==null)
			return null;
		
		JsonUser jsonUser = new JsonUser();
		jsonUser.setUserID(aUserID);
		
		JSONObject jsonConfig = getJsonConfig();
		
		Attribute attrUserName 	= entryUser.get(jsonConfig.getString(AuthConfig._LDAP_USERNAME));
		if(attrUserName!=null)
		{
			jsonUser.setUserName(attrUserName.getString());
		}
		
		Attribute attrUserRoles = entryUser.get(jsonConfig.getString(AuthConfig._LDAP_USERROLES));
		if(attrUserRoles!=null)
		{
			jsonUser.setUserRoles(attrUserRoles.getString(), AuthConfig._CFG_ROLES_SEPARATOR);
		}
		
		return jsonUser;
    }
    
	public String getConfigKey() {
		return this.configName;
	}
	
	public void setConfigKey(String aConfigName) {
		this.configName = aConfigName;
	}

	
    public static void main(String args[]) throws LdapException, CursorException 
    {    	
    	String testServiceDN1 = "CN=NLS Atlassian 1,OU=NLS,OU=Department,DC=NECSAPSIN,DC=COM";
    	String testServicePwd = AuthMgr.deobfuscate("{obfc}NVNlZWJjZnU2cjZpMXQyeWFAODE1MmEz");
    	
    	LDAPMgr ldap = new LDAPMgr("sin-sav-dc-03.necsapsin.com", 389);

    	ldap.bindServiceAcct(testServiceDN1, testServicePwd);
    	
    	String sSearchUID = "nls_atlassian1";
    	String sPWD = testServicePwd;
    	
    	System.out.println("Trying to auth "+sSearchUID+" : "+
    			ldap.testAuth(
    					sSearchUID, 
    					sPWD));

    	ldap.unbindServiceAcct();
    	
    }

}
