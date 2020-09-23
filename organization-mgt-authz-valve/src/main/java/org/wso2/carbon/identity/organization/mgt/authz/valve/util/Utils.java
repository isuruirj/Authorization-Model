package org.wso2.carbon.identity.organization.mgt.authz.valve.util;

import org.apache.catalina.connector.Request;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

public class Utils {

    public static String getTenantDomainFromURLMapping(Request request) {

        String requestURI = request.getRequestURI();
        String domain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

        if (requestURI.contains("/t/")) {
            String temp = requestURI.substring(requestURI.indexOf("/t/") + 3);
            int index = temp.indexOf('/');
            if (index != -1) {
                temp = temp.substring(0, index);
                domain = temp;
            }
        }
        return domain;
    }

    /**
     * Checks whether the tenantDomain from URL mapping and the tenantDomain get from the user name are same.
     *
     * @param authenticationContext Context of the authentication
     * @param request               authentication request
     * @return true if valid request
     */
    public static boolean isUserBelongsToRequestedTenant(AuthenticationContext authenticationContext, Request request) {

        String tenantDomainFromURLMapping = getTenantDomainFromURLMapping(request);
        User user = authenticationContext.getUser();
        String userDomain = user.getTenantDomain();
        return tenantDomainFromURLMapping.equals(userDomain);
    }
}
