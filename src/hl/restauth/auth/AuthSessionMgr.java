package hl.restauth.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalCause;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import hl.common.CryptoUtil;

public class AuthSessionMgr {
    
	
	private static IAuthTokenGenerator authTokenGenerator 	= null;
	private static AuthSessionMgr instance = null;
	
	private LoadingCache<String, String> cacheAuthSession = null;
	private Map<String, List<String>> mapUIDAuth = null;
	private int iMaxSessionAllows = 1;
	
	private static String _SESSION 						= "session";
	private static String _SESSION_TIMEOUT_SECS 		= "timeout.secs";
	private static String _SESSION_MAX_LIFESPAN_MINS 	= "max-lifespan.mins";
	private static String _SESSION_PER_USER				= "per-user.allow";
	
	private static String _TOKEN_GEN_CLASSNAME = "IAuthTokenGenerator.implementation";
	
	private static JSONObject jsonConfig = AuthConfig.getInstance().getAuthConfig(_SESSION);
	
	private AuthSessionMgr()
	{
		
		long lTimeoutInSecs = 300; //5 min
		
		if(jsonConfig.has(_SESSION_TIMEOUT_SECS))
		{
			lTimeoutInSecs = jsonConfig.getLong(_SESSION_TIMEOUT_SECS);
			if(lTimeoutInSecs<=0)
				lTimeoutInSecs = 300;
		}
		
		if(jsonConfig.has(_SESSION_PER_USER))
		{
			iMaxSessionAllows = jsonConfig.getInt(_SESSION_PER_USER);
			if(iMaxSessionAllows<=0)
				iMaxSessionAllows = 1;
		}
		
		cacheAuthSession = initCacheMap(lTimeoutInSecs, TimeUnit.SECONDS, 10000);
		mapUIDAuth = new HashMap<String, List<String>>();
		
		String sTokenGeneratorClassName = null;
		if(jsonConfig.has(_TOKEN_GEN_CLASSNAME))
		{
			sTokenGeneratorClassName = jsonConfig.getString(_TOKEN_GEN_CLASSNAME);
		}
		authTokenGenerator = initAuthTokenGenerator(sTokenGeneratorClassName);
	}
	
	private IAuthTokenGenerator initAuthTokenGenerator(String aTokenGeneratorClassName)
	{
		IAuthTokenGenerator tokenGenerator = null;
		
		if(aTokenGeneratorClassName!=null && aTokenGeneratorClassName.trim().length()>0)
		{
			try {
				Class classTokenGen = Class.forName(aTokenGeneratorClassName);
				tokenGenerator = (IAuthTokenGenerator) classTokenGen.newInstance();
			}catch(Exception ex)
			{
				ex.printStackTrace();
			}
		}
		
		if(tokenGenerator==null)
		{
			tokenGenerator = new BaseAuthTokenGenerator();
		}
		
		return tokenGenerator;
	}
	
	
	public static AuthSessionMgr getInstance()
	{
		if(instance==null)
		{
			instance = new AuthSessionMgr();
		}
		
		return instance;
	}
	
	public boolean isValid(String aUserID, String aAuthToken)
	{		
		if(aAuthToken!=null && aAuthToken.length()>0)
		{
			String sCacheUserID = null;
			try {
				sCacheUserID = cacheAuthSession.get(aAuthToken);
				if(sCacheUserID.equals(""))
					sCacheUserID = null;
			} catch (ExecutionException e) {
			}
			
			String sDecodedAuthToken = authTokenGenerator.decodeToken(aAuthToken);
			
			if(sCacheUserID!=null && sCacheUserID.equals(aUserID) 
					&& sDecodedAuthToken.endsWith(aUserID))
			{
				authTokenGenerator.verifyToken(aUserID, sDecodedAuthToken, jsonConfig);
				
				
				//refresh timeout
				cacheAuthSession.put(aAuthToken, aUserID);
				return true;
			}
		}
		return false;
	}
	
	public boolean logoutUser(JsonUser jsonUser)
	{
		if(jsonUser!=null)
		{
			String sAuthToken = jsonUser.getAuthToken();
			
			if(invalidate(sAuthToken))
				return true;
			
			if(sAuthToken==null)
			{
				String sUserID = jsonUser.getUserID();
				if(sUserID!=null)
				{
					List<String> listUserAuthToken = mapUIDAuth.remove(sUserID);
					if(listUserAuthToken!=null)
					{
						for(String sUserAuthToken : listUserAuthToken)
						{
							cacheAuthSession.invalidate(sUserAuthToken);
						}
						return true;
					}
				}
			}
		}
		return false;
	}
	
	public boolean invalidate(String aAuthToken)
	{
		if(aAuthToken!=null)
		{
				String sUserID = null;
				
				try {
					sUserID = cacheAuthSession.get(aAuthToken);
					if(sUserID.equals(""))
						sUserID = null;
				} catch (ExecutionException e) {
				}
				
				cacheAuthSession.invalidate(aAuthToken);
				if(sUserID!=null)
				{
					List<String> listAuthSessions = mapUIDAuth.get(sUserID);
					listAuthSessions.remove(aAuthToken);
					if(listAuthSessions.size()>0)
					{
						mapUIDAuth.put(sUserID, listAuthSessions);
					}else
					{
						mapUIDAuth.remove(sUserID);
					}
					return true;
				}
		}
		return false;
	}
	
	public JsonUser register(JsonUser jsonUser)
	{
		if(jsonUser==null || jsonUser.getUserID()==null)
			return null;
		
		String sUserID = jsonUser.getUserID();
		
		if(sUserID.trim().length()>0)
		{
			String sAuthToken = authTokenGenerator.generateToken(jsonUser);

			List<String> listExistingAuthToken = mapUIDAuth.get(sUserID);
			if(listExistingAuthToken!=null)
			{
				if(listExistingAuthToken.size()>=iMaxSessionAllows)
				{
					String sExistingAuthToken = listExistingAuthToken.get(0);
					cacheAuthSession.invalidate(sExistingAuthToken);
					listExistingAuthToken.remove(sExistingAuthToken);
				}
			}
			else
			{
				listExistingAuthToken = new ArrayList<String>();
			}
			
			cacheAuthSession.put(sAuthToken, sUserID);
			
			listExistingAuthToken.add(sAuthToken);
			mapUIDAuth.put(sUserID, listExistingAuthToken);
				
			jsonUser.setAuthToken(sAuthToken);
		}
		else
		{
			jsonUser = null;
		}
		return jsonUser;
	}
	

	private LoadingCache<String, String> initCacheMap(
			long aDuration, TimeUnit aTimeUnit, long aMaxCapaity)
	{
		
	    CacheLoader<String, String> loader;
	    loader = new CacheLoader<String, String>() {

			@Override
			public String load(String key) throws Exception {
				return "";
			}
	    };

		return CacheBuilder.newBuilder()
	      .maximumSize(aMaxCapaity)
	      .expireAfterWrite(aDuration, aTimeUnit)
	      .removalListener(
		    	new RemovalListener<Object, Object>()
		      	{
					public void onRemoval(RemovalNotification<Object, Object> removal) {
						onItemRemoval(
								removal.getKey().toString(), 
								removal.getValue(),
								removal.getCause());
					}
				}
	      )
	      .build(loader);
		
	}
	
	private void onItemRemoval(String aItemKey, Object aItem, RemovalCause aExpiryCause)
	{
		
		System.out.println("[mockauth.session]"+aExpiryCause.name()+"-"+String.valueOf(aItem)+":"+CryptoUtil.obfuscate(aItemKey));
	}
	
    public static void main(String args[]) 
    {    	
    }
}
