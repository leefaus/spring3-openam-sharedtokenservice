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
 *
 * $Id: OpenSSOProcessingFilter.java,v 1.1 2009-02-26 18:20:54 wstrange Exp $
 *
 */
package com.sun.identity.provider.springsecurity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;


import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.shared.debug.Debug;

/**
 * Implementation of filter which is responsible for processing authentication requests.
 * @see AbstractAuthenticationProcessingFilter
 */
public class OpenSSOProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private static Debug debug = Debug.getInstance("amSpring");
    public static final String SPRING_SECURITY_LAST_USERNAME_KEY = "SPRING_SECURITY_LAST_USERNAME";

    public OpenSSOProcessingFilter() {
        super("/ssologin");
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        SSOToken token = OpenSSOUtil.obtainSSOToken(request);
        String username = OpenSSOUtil.obtainUsername(token);
        if( debug.messageEnabled() )
            debug.message("username: " + (username == null ? "is null" : username));

        if (username == null) {
            throw new BadCredentialsException("User not logged in via Portal! SSO user cannot be validated!");
        }

        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(username, token);



        // Place the last username attempted into HttpSession for views
        request.getSession().setAttribute(SPRING_SECURITY_LAST_USERNAME_KEY, username);

        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /*public int getOrder() {
        return FilterChainOrder.AUTHENTICATION_PROCESSING_FILTER;
    }*/

   /* @Override
    public String getDefaultFilterProcessesUrl() {
        return "/ssologin";
    }*/

    // this sets details of the authentication, NOT the user details
    // default is WebAuthenticationDetails (e.g. IP address, etc.)
    // todo: We should overide with the OpenSSO information.
    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        Object o = authenticationDetailsSource.buildDetails(request);
//        if (debug.messageEnabled()) {
//            debug.message("Details object= " + o.getClass() + " val=" + o);
//        }
        authRequest.setDetails(o);
    }
}
