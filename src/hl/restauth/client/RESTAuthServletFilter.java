package hl.restauth.client;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;

import hl.restauth.accessctrl.AccessConfig;
import hl.restauth.auth.JsonUser;

public class RESTAuthServletFilter implements Filter {

	@Override
	public void destroy() {
		// nothing to destroy
		
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest httpReq = (HttpServletRequest) req;
		
		JSONObject json = new JSONObject();
		json.put(JsonUser._UID, httpReq.getHeader(JsonUser._UID));
		json.put(JsonUser._AUTHTOKEN, httpReq.getHeader(JsonUser._AUTHTOKEN));
		//
		json.put(AccessConfig._CFG_ENDPOINT_URL, httpReq.getPathInfo());
		json.put(AccessConfig._CFG_HTTP_METHOD, httpReq.getMethod());
		json.put(AccessConfig._CFG_IP, httpReq.getRemoteAddr());

		System.out.println("["+RESTAuthServletFilter.class.getName()+"]"+json.toString());
		chain.doFilter(httpReq, resp);
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// nothing to init
		
	}
}
