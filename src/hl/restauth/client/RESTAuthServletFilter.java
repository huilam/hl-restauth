package hl.restauth.client;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import hl.restauth.AuthUtil;
import hl.restauth.JsonAuth;
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
		
		JsonAuth json = new JsonAuth();
		json.setConsumerUID(httpReq.getHeader(JsonUser._UID));
		json.setConsumerAuthToken(httpReq.getHeader(JsonUser._AUTHTOKEN));
		json.setConsumerIP(AuthUtil.getClientIP(httpReq));
		//
		json.setResourceEndpointURL(httpReq.getPathInfo());
		json.setResourceHttpMethod(httpReq.getMethod());
		//
		System.out.println("["+RESTAuthServletFilter.class.getName()+"]"+json.toString());
		chain.doFilter(httpReq, resp);
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// nothing to init
		
	}
}
