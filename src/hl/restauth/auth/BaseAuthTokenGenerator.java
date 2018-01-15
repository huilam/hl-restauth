package hl.restauth.auth;

import java.util.Random;

import org.json.JSONObject;

public class BaseAuthTokenGenerator implements IAuthTokenGenerator {

	private final static Random rand = new Random(System.currentTimeMillis());
	
	private final static String _SEPARATOR = String.valueOf(rand.nextFloat());
	
	@Override
	public String generateToken(JsonUser aJsonUser)
	{
		StringBuffer sbAuthToken = new StringBuffer();
		sbAuthToken.append(System.currentTimeMillis());
		sbAuthToken.append(_SEPARATOR).append("1");
		sbAuthToken.append(aJsonUser.getClientIP());
		sbAuthToken.append(_SEPARATOR).append("2");
		sbAuthToken.append(aJsonUser.getUserAgent());
		sbAuthToken.append(_SEPARATOR).append("3");
		sbAuthToken.append(aJsonUser.getUserID());
		return AuthMgr.obfuscate(sbAuthToken.toString());
	}
	
	@Override	
	public String decodeToken(String aAuthToken)
	{
		return AuthMgr.deobfuscate(aAuthToken);
	}

	@Override
	public boolean verifyToken(String aUserID, String aAuthToken, JSONObject aConfigJson) {
		String sDecodedToken = decodeToken(aAuthToken);
		
		///
		if(aConfigJson!=null && aConfigJson.has("max-lifespan.mins"))
		{
			long lMaxLifeSpan = aConfigJson.getLong("max-lifespan.mins");
			if(lMaxLifeSpan>0)
			{
				lMaxLifeSpan = lMaxLifeSpan * 60000; //Convert to milliseconds
				
				int iPos = sDecodedToken.indexOf(_SEPARATOR+"1");
				if(iPos>-1)
				{
					long lLoginTime = Long.parseLong(sDecodedToken.substring(0, iPos));
					long lLifespanDuration  = System.currentTimeMillis() - lLoginTime;
					
					if(lLifespanDuration>=lMaxLifeSpan)
					{
						//authtoken exists max life span
						return false;
					}
				}
			}
		}
		///
		int iPos = sDecodedToken.indexOf(_SEPARATOR+"3");
		if(iPos>-1)
		{
			String sUserID = sDecodedToken.substring(iPos);
			if(sUserID.equals(aUserID))
				return true;
		}
		///
		
		return false;
	}
	
	public static void main(String[] args)
	{
		System.out.println(_SEPARATOR);
	}

}
