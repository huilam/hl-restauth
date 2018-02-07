package hl.restauth.accessctrl;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import hl.common.PropUtil;
import hl.restauth.auth.AuthConfig;


public class AccessConfig {
	
	public final static String _PROP_FILENAME 				= "accessctrl.properties";
	
	public static String _CFG_SYSTEM						= "system.";
	public static String _CFG_ACCESS_POLICY					= "access-policy";
	
	public static String _CFG_SYS_MULTIVALUES_SEPARATOR		= _CFG_SYSTEM+"multivalues.separator";
	public static String _CFG_SYS_ACCESS_POLICY_WILDCARD	= _CFG_SYSTEM+_CFG_ACCESS_POLICY+".wildcard";

	public static String _CFG_PROVIDERS						= "providers.";
	public static String _CFG_CONSUMERS						= "consumers.";

	public static String _CFG_ACCPOLICY_PRECEDENCE 			= _CFG_ACCESS_POLICY+".precedence";

	public static String _CFG_ALLOW							= "allow-";
	public static String _CFG_DENIED						= "denied-";
	
	public static String _CFG_IP							= "ip";
	public static String _CFG_ROLE							= "role";
	public static String _CFG_UID							= "uid";
	
	public static String _CFG_ENDPOINT_URL					= "endpoint-url";
	public static String _CFG_HTTP_METHOD					= "http-method";
	
	private Properties propAll = new Properties();
	private Properties propEndpointCfgMapping = new Properties();
	private Map<String, String[]> mapConfig = new HashMap<String, String[]>();
	//
	private static AccessConfig instance = null;
	//
	public static AccessConfig getInstance() 
	{
		if(instance==null)
		{
			instance = new AccessConfig();
		}
		return instance;
	}
	
	public String getPropValue(String aPropKey, String aDefaultValue)
	{
		String sValue = propAll.getProperty(aPropKey);
		if(sValue==null)
			sValue = aDefaultValue;
		return sValue;
	}
	
	public String getMultiValSeparator()
	{
		return getPropValue(_CFG_SYS_MULTIVALUES_SEPARATOR, ",");
	}
	
	public String getAccessPolicyWildcard()
	{
		return getPropValue(_CFG_SYS_ACCESS_POLICY_WILDCARD, "*");
	}
	
	public Map<String, String[]> getAccessConfig()
	{
		if(mapConfig.size()==0)
		{
			String sSeparator = getMultiValSeparator();
			for(Object oPropKey : propAll.keySet())
			{
				String sValue = propAll.getProperty(oPropKey.toString());
				if(sValue==null)
				{
					sValue = "";
				}
				String[] sPropValues = sValue.trim().split(sSeparator);
				mapConfig.put(oPropKey.toString(), sPropValues);
			}
		}
		return mapConfig;
	}
	
	public Map<String, String[]> getConsumerAccPolicies(String aEndPoint, String aHttpMethod)
	{
		return getAccPolicies(aEndPoint, aHttpMethod, _CFG_CONSUMERS);
	}
	
	public Map<String, String[]> getProviderAccPolicies(String aEndPoint)
	{
		return getAccPolicies(aEndPoint, null, _CFG_PROVIDERS);
	}
	
	private Map<String, String[]> getAccPolicies(String aEndPoint, String aHttpMethod, String aConfigType)
	{
		Map<String, String[]> mapPolicies = new LinkedHashMap<String, String[]>();
		String sConfigPrefx = _CFG_SYSTEM + aConfigType + _CFG_ACCPOLICY_PRECEDENCE;
		
		String sEndPointMappingName = propEndpointCfgMapping.getProperty(aEndPoint);
		String sApiPrefix = sEndPointMappingName+"."+aConfigType+_CFG_ACCESS_POLICY+".";
		
		if(aHttpMethod!=null)
		{
			sApiPrefix = sApiPrefix+aHttpMethod+".";
		}
		
		Map<String, String[]> mapConfig = getAccessConfig();
		String[] accessPolicies = mapConfig.get(sConfigPrefx);
		if(accessPolicies!=null)
		{
			for(String sPolicy : accessPolicies)
			{
				String sConfigKey 	= sApiPrefix+sPolicy;
				String[] sValues 	= mapConfig.get(sConfigKey);
				//
				mapPolicies.put(sPolicy, sValues);
			}
		}
		return mapPolicies;
	}
	
	public void init() 
	{
		try {
			propAll = PropUtil.loadProperties(_PROP_FILENAME);
		} catch (IOException e) {
			System.err.println(e);
			propAll = new Properties();
		}
		mapConfig.clear();
		propEndpointCfgMapping.clear();
		
		for(Object oKey : propAll.keySet())
		{
			String sKey = oKey.toString();
			if(sKey.endsWith(_CFG_ENDPOINT_URL))
			{
				String[] sKeySegs = sKey.split("\\."); 
				propEndpointCfgMapping.put(propAll.get(oKey), sKeySegs[0]);
				System.out.println(propAll.get(oKey)+":"+sKeySegs[0]);
			}
		}
	}
}