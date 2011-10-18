package com.sun.identity.provider.springsecurity;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import com.iplanet.sso.SSOToken;

public interface OpenSSOGrantedAuthoritiesMapper {

	Collection<GrantedAuthority> getGrantedAuthorities(SSOToken ssoToken) throws Exception;
	
}
