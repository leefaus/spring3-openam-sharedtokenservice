/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2008 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * 
 * "Portions Copyrighted 2008 Robert Dale <robdale@gmail.com>"
 * "Portions Copyrighted 2009 Warren Strange <warren.strange@gmail.com>"
 *
 * $Id: OpenSSOAuthenticationProvider.java,v 1.1 2009-02-26 18:18:53 wstrange Exp $
 *
 */
package com.sun.identity.provider.springsecurity;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.iplanet.sso.SSOToken;
import com.sun.identity.shared.debug.Debug;

/**
 * @see AuthenticationProvider
 */
public class OpenSSOAuthenticationProvider implements AuthenticationProvider {

    private static Debug debug = Debug.getInstance("amSpring");

    /*static {
        try {
            Class.forName(SystemProperties.class.getName());
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException(e);
        }
    }*/
    
    private OpenSSOGrantedAuthoritiesMapper grantedAuthoritiesMapper = new OpenSSOSimpleAuthoritiesPopulator();

    /**
     * authenticate the access request.
     *
     * Note by this point the user has already been granted an sso token
     * (i.e. they have already authenticated because they were redirected
     * to opensso).
     *
     * If the user has any group membership we turn those into
     * GrantedAuthortities (roles in Spring terminolgy).
     * @see  OpenSSOSimpleAuthoritiesPopulator
     *
     * Note that a failure to retrieve OpenSSO roles does not result in
     * an non revcoverable exception (but we should revist this decision). In theory
     * we can continue with authentication only. The user will have no
     * GrantedAuthorities.
     *
     * @param authentication
     * @return authentication token - possibly withe ROLE_*  authorities.
     * 
     * @throws org.springframework.security.core.AuthenticationException
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    	if( debug.messageEnabled())
            debug.message("Authentication: " + authentication);
        
        String principal = (String) authentication.getPrincipal();

        // hack alert
        // We pass in the SSOToken as the credential (.e.g the password)
        // this is probably confusing - and we should refactor to use a
        // proper OpenSSOAuthenitcationToken.
        SSOToken ssoToken = (SSOToken) authentication.getCredentials();

        try {
            Collection<GrantedAuthority> grantedAuthorities = grantedAuthoritiesMapper.getGrantedAuthorities(ssoToken);
            authentication = buildAuthenticationWithAuthorities(authentication, grantedAuthorities);
        } catch (Exception ex) {
             //throw new AuthenticationServiceException("Exception trying to get AMIdentity", ex);
            // Note: We eat the exception
            // The authentication can still succeed - but there will be no
            // granted authorities (i.e. no roles granted).
            // This is arguably the right thing to do here
            debug.error("Exception Trying to get AMIdentity", ex);
        }

        return authentication;
    }

    public boolean supports(Class authenticationClass) {
        if (debug.messageEnabled()) {
        	debug.message("Supported class query for: " + authenticationClass);
        }
        return (authenticationClass == UsernamePasswordAuthenticationToken.class) 
        		|| (authenticationClass == PreAuthenticatedAuthenticationToken.class);
    }
    
    public OpenSSOGrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
		return grantedAuthoritiesMapper;
	}

	public void setGrantedAuthoritiesMapper(OpenSSOGrantedAuthoritiesMapper grantedAuthoritiesMapper) {
		this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
	}

	private Authentication buildAuthenticationWithAuthorities(Authentication anExistingAuthentication, Collection<GrantedAuthority> someGrantedAuthorities) {

    	Authentication completeAuthentication = null;
    	
    	try {
			Constructor<? extends Authentication> constructor = anExistingAuthentication.getClass().getConstructor(Object.class, Object.class, Collection.class);
			completeAuthentication = constructor.newInstance(anExistingAuthentication.getPrincipal(), anExistingAuthentication.getCredentials(), someGrantedAuthorities);
		} catch (SecurityException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		} catch (NoSuchMethodException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		} catch (IllegalArgumentException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		} catch (InstantiationException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		} catch (IllegalAccessException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		} catch (InvocationTargetException e) {
			debug.message("Failed to build authentication object with granted authorities", e);
		}
    	
    	return completeAuthentication;
    }
}
