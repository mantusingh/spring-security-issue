package com.ms.demo;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;


public class RoleBasedAuthenticationSuccessHandler implements
		AuthenticationSuccessHandler {
	private final Logger glLogger = LogManager.getLogger(getClass());
	private Map<String, String> roleUrlMap;

	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		glLogger.info("Auth request..");
		securityContextRepository.saveContext(SecurityContextHolder.getContext(),request,response);


	}
	private String getLegacyRole(SkyUser skyUser) {

		return "";
	}

	public void setRoleUrlMap(Map<String, String> roleUrlMap) {
		this.roleUrlMap = roleUrlMap;
	}
	public Map<String, String> getRoleUrlMap() {
		return roleUrlMap;
	}


}
