package hl.restauth.accessctrl;

import org.json.JSONObject;

public class JsonAccessEntity extends JSONObject{

	public JsonAccessEntity()
	{
		super();
	}
	
	public JsonAccessEntity(String aJsonString)
	{
		super(aJsonString);
	}
	
	//
	public String getAttribute(String aAttrName)
	{
		if(has(aAttrName))
			return getString(aAttrName);
		else
			return null;
	}
	
	public String getIP()
	{
		return getAttribute(AccessConfig._CFG_IP);
	}
	
	public String getUID()
	{
		return getAttribute(AccessConfig._CFG_UID);
	}
	
	public String getRoles()
	{
		return getAttribute(AccessConfig._CFG_ROLE);
	}
	
}
