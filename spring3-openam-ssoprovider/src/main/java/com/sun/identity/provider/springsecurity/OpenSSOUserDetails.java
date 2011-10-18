/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sun.identity.provider.springsecurity;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 *
 * @author warrenstrange
 */
public class OpenSSOUserDetails implements UserDetails {

    private SSOToken ssoToken;

    public OpenSSOUserDetails(SSOToken ssoToken) {
        this.ssoToken = ssoToken;
    }
    
    public Collection<GrantedAuthority> getAuthorities() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getPassword() {
        return "**secret**";
    }

    public String getUsername() {
        try {
            return ssoToken.getPrincipal().getName();
        } catch (SSOException ex) {
           throw new AuthorizationServiceException("Cant access SSOToken",ex);
        }
    }

    public boolean isAccountNonExpired() {
        return true;
    }

    public boolean isAccountNonLocked() {
       return true;
    }

    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return true;
    }

}
