package com.sun.identity.provider.springsecurity;

import javax.servlet.http.HttpServletRequest;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.shared.debug.Debug;

public class OpenSSOUtil {

    private static Debug debug = Debug.getInstance("amSpring");

    static SSOToken getToken(HttpServletRequest request) {
        SSOToken token = null;
        try {
            SSOTokenManager manager = SSOTokenManager.getInstance();
            token = manager.createSSOToken(request);
            if( debug.messageEnabled()) debug.message("Got SSOToken OK. token=" + token);

        } catch (Exception e) {
            debug.error("Error creating SSOToken", e);
        }
        return token;
    }
    
    static SSOToken obtainSSOToken(HttpServletRequest request) {
        request = HttpUtil.unwrapOriginalHttpServletRequest(request);
        HttpUtil.printCookies(request);
        SSOToken token = getToken(request);
        if (token != null && isTokenValid(token)) {
            return token;
        }
        return null;
    }
    
    static String obtainUsername(SSOToken token) {
        String result = null;
        if (token != null) {
            try {
                result = token.getProperty("UserId");
            } catch (SSOException e) {
                debug.error("Error getting UserId from SSOToken", e);
            }
        }
        return result;
    }

    private static boolean isTokenValid(SSOToken token) {
        if (token == null) {
            throw new IllegalArgumentException("SSOToken is null");
        }

        boolean result = false;
        try {
            SSOTokenManager manager = SSOTokenManager.getInstance();
            result = manager.isValidToken(token);
        } catch (Exception e) {
            debug.error("Error validating SSOToken", e);
        }
        return result;
    }

}
