/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.mgt.authz.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.handler.HandlerManager;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.organization.mgt.authz.valve.internal.OrganizationMgtAuthzValveServiceHolder;
import org.wso2.carbon.identity.organization.mgt.authz.valve.util.Utils;
import org.wso2.carbon.identity.organization.mgt.authz.service.OrgMgtAuthorizationContext;
import org.wso2.carbon.identity.organization.mgt.authz.service.model.OrgResourceConfigKey;
import org.wso2.carbon.identity.organization.mgt.authz.service.util.OrganizationMgtAuthzUtil;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;

public class OrganizationMgtAuthzValve extends ValveBase {

    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";
    private static final String AUTH_CONTEXT = "auth-context";

    private static final Log log = LogFactory.getLog(OrganizationMgtAuthzValve.class);

    public void invoke(Request request, Response response) throws IOException, ServletException {

        AuthenticationContext authenticationContext = (AuthenticationContext) request.getAttribute(AUTH_CONTEXT);

        if (authenticationContext != null && authenticationContext.getUser() != null && StringUtils
                .isNotEmpty(authenticationContext.getUser().getUserName())) {
            String contextPath = authenticationContext.getResourceConfig().getContext();
            String httpMethod = authenticationContext.getResourceConfig().getHttpMethod();
            // Check whether the request need to be handled by custom authorize handler
            ResourceConfig resourceConfigInOrgMgt = OrganizationMgtAuthzUtil.getInstance()
                    .getSecuredConfig(new OrgResourceConfigKey(authenticationContext.getResourceConfig().getContext(),
                            authenticationContext.getResourceConfig().getHttpMethod()));
            if (resourceConfigInOrgMgt == null) {
                getNext().invoke(request, response);
                return;
            }
            String requestURI = request.getRequestURI();
            String queryString = request.getQueryString();
            AuthorizationContext authorizationContext = new OrgMgtAuthorizationContext();

            if (resourceConfigInOrgMgt != null) {
                authorizationContext.setIsCrossTenantAllowed(resourceConfigInOrgMgt.isCrossTenantAllowed());
            }
            if (!isRequestValidForTenant(authenticationContext, (OrgMgtAuthorizationContext) authorizationContext,
                    request)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization to " + request.getRequestURI()
                            + " is denied because the authenticated user belongs to different tenant domain: "
                            + authenticationContext.getUser().getTenantDomain()
                            + " and cross-domain access is disabled.");
                }
                handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            if (resourceConfigInOrgMgt != null && StringUtils.isNotEmpty(resourceConfigInOrgMgt.getPermissions())) {
                authorizationContext.setPermissionString(resourceConfigInOrgMgt.getPermissions());
            }
            if (resourceConfigInOrgMgt != null && CollectionUtils.isNotEmpty(resourceConfigInOrgMgt.getScopes())) {
                authorizationContext.setRequiredScopes(resourceConfigInOrgMgt.getScopes());
            }
            authorizationContext.setContext(contextPath);
            ((OrgMgtAuthorizationContext) authorizationContext).setRequestUri(requestURI);
            authorizationContext.setHttpMethods(httpMethod);
            authorizationContext.setUser(authenticationContext.getUser());
            ((OrgMgtAuthorizationContext) authorizationContext).setQueryString(queryString);
            authorizationContext
                    .addParameter(OAUTH2_ALLOWED_SCOPES, authenticationContext.getParameter(OAUTH2_ALLOWED_SCOPES));
            authorizationContext
                    .addParameter(OAUTH2_VALIDATE_SCOPE, authenticationContext.getParameter(OAUTH2_VALIDATE_SCOPE));

            String tenantDomainFromURLMapping = Utils.getTenantDomainFromURLMapping(request);
            authorizationContext.setTenantDomainFromURLMapping(tenantDomainFromURLMapping);
            List<AuthorizationManager> authorizationManagerList = OrganizationMgtAuthzValveServiceHolder.getInstance()
                    .getAuthorizationManagerList();
            AuthorizationManager authorizationManager = HandlerManager.getInstance()
                    .getFirstPriorityHandler(authorizationManagerList, true);
            try {
                AuthorizationResult authorizationResult = authorizationManager.authorize(authorizationContext);
                if (authorizationResult.getAuthorizationStatus().equals(AuthorizationStatus.GRANT)) {
                    getNext().invoke(request, response);
                } else {
                    handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_FORBIDDEN);
                }
            } catch (AuthzServiceServerException e) {
                handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            getNext().invoke(request, response);
        }
    }

    private void handleErrorResponse(AuthenticationContext authenticationContext, Response response, int error)
            throws IOException {

        StringBuilder value = new StringBuilder(16);
        value.append("realm user=\"");
        if (authenticationContext.getUser() != null) {
            value.append(authenticationContext.getUser().getUserName());
        }
        value.append('\"');
        response.setHeader(AUTH_HEADER_NAME, value.toString());
        response.sendError(error);
    }

    /**
     * Checks the request is valid for Tenant.
     *
     * @param authenticationContext Context of the authentication.
     * @param authorizationContext  Context of the authorization.
     * @param request               Authentication request.
     * @return True if valid request.
     */
    private boolean isRequestValidForTenant(AuthenticationContext authenticationContext,
                                            OrgMgtAuthorizationContext authorizationContext, Request request) {

        return (Utils.isUserBelongsToRequestedTenant(authenticationContext, request) || authorizationContext
                .isCrossTenantAllowed());
    }
}
