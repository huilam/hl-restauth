package hl.restauth;

import java.util.regex.Pattern;
import jakarta.servlet.http.HttpServletRequest;
import hl.restauth.auth.AuthConfig;

public class AuthUtil {
	
	private static final String CFG_PREFIX 					= "auth.reverse-proxies.";
	private static final String REVERSE_PROXIES_IP 			= CFG_PREFIX+".ip";
	private static final String REVERSE_CLIENTIP_HEADERS 	= CFG_PREFIX+".client-ip.headers";
	
	private static String[] rproxies_ip 				= null;
	private static String[] rproxies_clientip_headers 	= null;	
	
	private static Pattern pattIPv4 = Pattern.compile("(:?[0-9]{1,3}\\.){3}[0-9]{1,3}"); //255.255.255.0 , 127.0.0.1
	private static Pattern pattIPv6 = Pattern.compile("(:?[0-9a-fA-F]{0,2}:){7}[0-9a-fA-F]{0,2}"); //::::::: AAFF:0000:0000:0000:0000:0000:0000:aaff%99
	
	
    /////////////////////////////////////////////////////////////////
	public static boolean isValidIP(String aIP)
	{
		if(aIP.indexOf(":")>-1)
		{
			if(pattIPv6.matcher(aIP).find())
			{
				return true;
			}
		}
		else if(pattIPv4.matcher(aIP).find())
		{
			return true;
		}
		return false;
	}
	
    public static String getClientIP(HttpServletRequest aHttpReq)
    {
    	String sClientIP = aHttpReq.getRemoteAddr();
    	
    	if(rproxies_ip==null)
    	{
    		rproxies_ip = getConfigMultiValues(REVERSE_PROXIES_IP);
    	}
    	
    	for(String sProxyIp : rproxies_ip)
    	{
    		if(sClientIP.equals(sProxyIp))
    		{
    			if(rproxies_clientip_headers==null)
    			{
    				rproxies_clientip_headers = getConfigMultiValues(REVERSE_CLIENTIP_HEADERS);
    			}
    			
    			for(String sHeaderName : rproxies_clientip_headers)
    	    	{
    				String sHeaderValue = aHttpReq.getHeader(sHeaderName);
    				if(sHeaderValue!=null && isValidIP(sHeaderValue))
    				{
    					return sHeaderValue;
    				}
    	    	}
    			
    		}
    	}
    	
    	return sClientIP;
    }
    
    private static String[] getConfigMultiValues(String aPropKey)
    {
    	String[] sValues 		= new String[]{};
    	String sValuesString 	= AuthConfig.getInstance().getPropValue(aPropKey);
		if(sValuesString!=null)
		{
			sValues = sValuesString.trim().split(",");
		}
		return sValues;
    }
    
    public static void main(String args[]) throws Exception
    {
    	String[] sIPs = new String[]{"127.0.0.1","255.255.255.0","0.0.0.0","AAFF:0000:0000:0000:0000:0000:0000:aaff%99",":::::::"};
    	
    	for(String sIP : sIPs)
    	{
        	System.out.println(sIP+":"+AuthUtil.isValidIP("127.0.0.1"));
    	}
    }
}