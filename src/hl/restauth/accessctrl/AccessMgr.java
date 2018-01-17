package hl.restauth.accessctrl;

import java.io.IOException;
import java.util.Map;

import org.json.JSONObject;
import hl.restauth.JsonAuth;
import hl.restauth.auth.AuthMgr;
import hl.restauth.auth.JsonUser;

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
	
	public boolean isConsumerAllow(String aEndpoint, String aHttpMethod, JsonAuth aJsonAuth)
	{
		if(aJsonAuth.getConsumerRoles()==null)
		{
			String sUid = aJsonAuth.getConsumerUID();
			JsonUser jsonUser = AuthMgr.getUser(sUid);
			aJsonAuth.setConsumerRoles(jsonUser.getUserRoles());
		}
		
		Map<String, String[]> map = accessConfig.getConsumerAccPolicies(aEndpoint, aHttpMethod);
		return isAccessAllowed(map, aJsonAuth.getConsumer());
	}
	
	public boolean isProviderAllow(String aEndpoint, String aHttpMethod, JsonAuth aJsonAuth)
	{
		Map<String, String[]> map = accessConfig.getProviderAccPolicies(aEndpoint);
		return isAccessAllowed(map, aJsonAuth.getProvider());
	}
	
	private boolean isAccessAllowed(Map<String, String[]> aMapAccessPolicies, JSONObject aJsonAccessCandidate)
	{
		boolean isAllowAccess = false;
		
		if(aJsonAccessCandidate==null || aJsonAccessCandidate.toString().trim().length()<=2)
			return false;
		
		if(aMapAccessPolicies==null)
			return false;
		
		System.out.println(" ? isAccessAllowed : "+aJsonAccessCandidate.toString());
		
		
		for(String sAccessPolicy : aMapAccessPolicies.keySet())
		{
			int iPos = sAccessPolicy.indexOf("-");
			if(iPos>-1)
			{
				String sAccessRule 				= sAccessPolicy.substring(iPos+1);
				String[] sAccessConfigValues 	= sAccessRule.split(accessConfig.getMultiValSeparator());
				//
				if(sAccessConfigValues!=null && sAccessConfigValues.length>0)
				{
					for(String sAccessType : sAccessConfigValues)
					{
						if(!aJsonAccessCandidate.has(sAccessType))
							continue;
							
						String sCandidateVals = aJsonAccessCandidate.getString(sAccessType);
						if(sCandidateVals==null)
							continue;
						
						String[] sConfigVals = aMapAccessPolicies.get(sAccessPolicy);
						if(sConfigVals==null)
							continue;
						
System.out.println("	- AccessPolicy='"+sAccessPolicy+"' : '"+String.join(",", sConfigVals)+"'");			
						
System.out.println("	- Comparing '"+sCandidateVals+"' ...");			

						String[] sCandidateValues = sCandidateVals.split(accessConfig.getMultiValSeparator());
						for(String sReqVal : sCandidateValues)
						{
							boolean isMatch = false;
							for(String sConfigVal : sConfigVals)
							{
System.out.print("  		- Matching '"+sReqVal+"' with config'"+sConfigVal+"' ... ");
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
								
								System.out.println(isMatch);	
								
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
    	JsonAuth jsonAuth = new JsonAuth();
    	jsonAuth.setProviderIP("127.0.0.1");
    	
    	jsonAuth.setConsumerIP("127.0.0.1");
    	jsonAuth.setConsumerRoles("admin,poweruser");
    	jsonAuth.setConsumerUID("onghuilam");
    	
    	String sURL = "/alerts";
    	String sHttpMethod = "";
    	
    	sHttpMethod = "GET";
    	System.out.println();
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonAuth));
    	
    	sHttpMethod = "POST";
    	System.out.println();
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonAuth));
    	
    	sHttpMethod = "PUT";
    	System.out.println();
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonAuth));
    	
    	sHttpMethod = "DELETE";
    	System.out.println();
    	System.out.println(sHttpMethod+" "+sURL+" : "+mgr.isConsumerAllow(sURL, sHttpMethod, jsonAuth));
    	
    	
    }
}
