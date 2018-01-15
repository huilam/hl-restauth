package hl.restauth.accessctrl;

import java.io.IOException;
import java.util.Map;

public class AccessMgr {

	private final static String VERSION 	= "0.1.0";
	//
	private AccessConfig accessConfig 		= null;
	
	public AccessMgr()
	{
		accessConfig = AccessConfig.getInstance();
		try {
			reinit();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void reinit() throws IOException
	{
		accessConfig.init();
	}
	
	
	public static String getVersion()
	{
		return VERSION;
	}
	
	public boolean isConsumerAllow(String aEndpoint, String aHttpMethod, JsonAccessEntity aJsonEntity)
	{
		Map<String, String[]> map = accessConfig.getConsumerAccPolicies(aEndpoint, aHttpMethod);
		return isAccessAllowed(map, aJsonEntity);
	}
	
	public boolean isProviderAllow(String aEndpoint, String aHttpMethod, JsonAccessEntity aJsonEntity)
	{
		Map<String, String[]> map = accessConfig.getProviderAccPolicies(aEndpoint);
		return isAccessAllowed(map, aJsonEntity);
	}
	
	private boolean isAccessAllowed(Map<String, String[]> aMapAccessPolicies, JsonAccessEntity aAccessCandidate)
	{
		boolean isAllowAccess = false;
		
		if(aMapAccessPolicies==null)
			return isAllowAccess;
		
		for(String sAccessPolicy : aMapAccessPolicies.keySet())
		{
			int iPos = sAccessPolicy.indexOf("-");
			if(iPos>-1)
			{
				String sAccessRule 				= sAccessPolicy.substring(iPos+1);
				String[] sAccessConfigValues 	= sAccessRule.split(accessConfig.getMultiValSeparator());
				if(sAccessConfigValues!=null && sAccessConfigValues.length>0)
				{
					for(String sAccessType : sAccessConfigValues)
					{
						String sCandidateVals = aAccessCandidate.getAttribute(sAccessType);
						if(sCandidateVals==null)
							continue;
						
						String[] sConfigVals = aMapAccessPolicies.get(sAccessPolicy);
						if(sConfigVals==null)
							continue;
						
						String[] sCandidateValues = sCandidateVals.split(accessConfig.getMultiValSeparator());
						for(String sReqVal : sCandidateValues)
						{
							boolean isMatch = false;
							for(String sConfigVal : sConfigVals)
							{
								if(sConfigVal.equalsIgnoreCase(accessConfig.getAccessPolicyWildcard()))
								{
									// match any
									isMatch = true;
								}
								else
								{
									if(sAccessType.equalsIgnoreCase(AccessConfig._CFG_IP))
									{
										//partial match from start
										isMatch = sReqVal.startsWith(sConfigVal);
									}
									else
									{
										//exact match
										isMatch = sReqVal.equals(sConfigVal);
									}
								}
								
								if(isMatch)
								{
									if(sAccessPolicy.startsWith(AccessConfig._CFG_DENIED))
										return false;
									else if(sAccessPolicy.startsWith(AccessConfig._CFG_ALLOW))
										return true;
								}	
							}
						}
					}
				}
			}
		}
		
		return isAllowAccess;
	}
    
    public static void main(String args[]) throws Exception 
    {
    	AccessMgr mgr = new AccessMgr();
    	JsonAccessEntity jsonEntity = new JsonAccessEntity();
    	jsonEntity.put(AccessConfig._CFG_IP, "127.0.0.1");
    	jsonEntity.put(AccessConfig._CFG_ROLE, "admin,poweruser");
    	jsonEntity.put(AccessConfig._CFG_UID, "onghuilam");
    	
    	String sURL = "/alerts";
    	String sHttpMethod = "";
    	
    	sHttpMethod = "GET";
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonEntity));
    	
    	sHttpMethod = "POST";
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonEntity));
    	
    	sHttpMethod = "PUT";
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonEntity));
    	
    	sHttpMethod = "DELETE";
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonEntity));
    	
    	
    }
}
