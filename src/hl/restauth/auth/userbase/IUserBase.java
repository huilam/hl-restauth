package hl.restauth.auth.userbase;

import org.json.JSONObject;

import hl.restauth.auth.JsonUser;

public interface IUserBase {

	public JsonUser getUser(String aUserID) throws Exception;
    public String getConfigKey();
    public JSONObject getJsonConfig();
}
