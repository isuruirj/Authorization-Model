package org.wso2.carbon.identity.organization.mgt.authz.service;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.util.ArrayList;
import java.util.List;

public class OrgMgtAuthorizationContext extends AuthorizationContext {

    private String context;
    private String httpMethods;
    private String requestUri;

    private User user;
    private String permissionString;
    private List<String> requiredScopes;
    private boolean isCrossTenantAllowed;
    private String tenantDomainFromURLMapping;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getPermissionString() {
        return permissionString;
    }

    public void setPermissionString(String permissionString) {
        this.permissionString = permissionString;
    }

    public boolean isCrossTenantAllowed() {
        return isCrossTenantAllowed;
    }

    public void setIsCrossTenantAllowed(boolean isCrossTenantAllowed) {
        this.isCrossTenantAllowed = isCrossTenantAllowed;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getHttpMethods() {
        return httpMethods;
    }

    public void setHttpMethods(String httpMethods) {
        this.httpMethods = httpMethods;
    }

    public String getTenantDomainFromURLMapping() {
        return tenantDomainFromURLMapping;
    }

    public void setTenantDomainFromURLMapping(String tenantDomainFromURLMapping) {
        this.tenantDomainFromURLMapping = tenantDomainFromURLMapping;
    }

    public List<String> getRequiredScopes() {

        if (requiredScopes == null) {
            return new ArrayList<>();
        }
        return requiredScopes;
    }

    public void setRequiredScopes(List<String> requiredScopes) {

        this.requiredScopes = requiredScopes;
    }

    public String getRequestUri() {

        return requestUri;
    }

    public void setRequestUri(String requestUri) {

        this.requestUri = requestUri;
    }
}
