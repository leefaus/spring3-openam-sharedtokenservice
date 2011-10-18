package com.sun.identity.provider.springsecurity;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;

import com.iplanet.sso.SSOToken;

public class OpenSSOPreAuthenticatedProcessingFilter extends
		AbstractPreAuthenticatedProcessingFilter {

	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
		// Return the username from the token, null if no valid token is available
		String principal = "";
		SSOToken token = OpenSSOUtil.obtainSSOToken(request);
		if (token != null) {
			principal = OpenSSOUtil.obtainUsername(token); 
		}
		return principal;
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
		return OpenSSOUtil.obtainSSOToken(request);
	}

}
