package hl.restauth.auth;

import org.json.JSONObject;

public interface IAuthTokenGenerator {

	abstract public String generateToken(JsonUser aJsonUser);
	abstract public String decodeToken(String aAuthToken);
	abstract public boolean verifyToken(String aUserID, String aAuthToken, JSONObject aConfigJson);
	
}
