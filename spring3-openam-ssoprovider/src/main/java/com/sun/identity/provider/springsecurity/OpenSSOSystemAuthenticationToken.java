package com.sun.identity.provider.springsecurity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;

public class OpenSSOSystemAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -6255363764105703984L;

	public static final Authentication SYSTEM_AUTHENTICATION;
	
	static {
		Collection<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
		grantedAuthorities.add(new GrantedAuthorityImpl("ROLE_COGNILYTICS_ADMIN"));
		SYSTEM_AUTHENTICATION = new OpenSSOSystemAuthenticationToken(grantedAuthorities);
	}
	
	private OpenSSOSystemAuthenticationToken(Collection<GrantedAuthority> someGrantedAuthorities) {
        super(someGrantedAuthorities);
        setAuthenticated(true);		
	}
	
	public Object getCredentials() {
		return "SYSTEM";
	}

	public Object getPrincipal() {
		return "Admin";
	}
}
