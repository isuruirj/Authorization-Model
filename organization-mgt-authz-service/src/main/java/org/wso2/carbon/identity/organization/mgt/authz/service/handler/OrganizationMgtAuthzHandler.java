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

package org.wso2.carbon.identity.organization.mgt.authz.service.handler;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.mgt.authz.service.OrgMgtAuthorizationContext;
import org.wso2.carbon.identity.organization.mgt.authz.service.OrganizationMgtAuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.Arrays;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_RESOURCE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_URLS_WITH_ORG_ID;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.URI_SPLITTER;

/**
 * Authorization handler to handle organization mgt related authorization.
 */
public class OrganizationMgtAuthzHandler extends AuthorizationHandler {

    private static final Log log = LogFactory.getLog(AuthorizationHandler.class);

    private static final String RESOURCE_PERMISSION_NONE = "none";

    @Override
    public AuthorizationResult handleAuthorization(AuthorizationContext authorizationContext)
            throws AuthzServiceServerException {

        // If context not found in org-mgt
        if (!(authorizationContext instanceof OrgMgtAuthorizationContext)) {
            return super.handleAuthorization(authorizationContext);
        }
        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        try {
            String orgId;
            String requestUri = ((OrgMgtAuthorizationContext) authorizationContext).getRequestUri();
            if (Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestUri)) {
                orgId = retrieveOrganizationId(requestUri, authorizationContext.getHttpMethods());
                User user = authorizationContext.getUser();
                String userDomain = user.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(userDomain);
                String permissionString = authorizationContext.getPermissionString();
                String[] allowedScopes = authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES) == null ? null :
                        (String[]) authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES);
                boolean validateScope = authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE) == null ? false :
                        (Boolean) authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE);
                if (StringUtils.isNotBlank(permissionString)) {
                    validatePermissions(authorizationResult, user, permissionString, orgId, tenantId);
                }
            } else {
                // Need to handle differently. For now grant access.
                // TODO
                authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            }
        } catch (UserStoreException e) {
            String errorMessage = "Error occurred while trying to authorize, " + e.getMessage();
            log.error(errorMessage);
            throw new AuthzServiceServerException(errorMessage, e);
        }
        return authorizationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "OrganizationMgtAuthorizationHandler";
    }

    @Override
    public int getPriority() {

        return 50;
    }

    private void validatePermissions(AuthorizationResult authorizationResult, User user, String permissionString,
                                     String orgId, int tenantId)
            throws org.wso2.carbon.user.api.UserStoreException {

        if (RESOURCE_PERMISSION_NONE.equalsIgnoreCase(permissionString)) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            return;
        }
        boolean isUserAuthorized = OrganizationMgtAuthorizationManager.getInstance()
                .isUserAuthorized(user, permissionString, CarbonConstants.UI_PERMISSION_ACTION, orgId, tenantId);
        if (isUserAuthorized) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
        }
    }

    private String retrieveOrganizationId(String requestPath, String getHttpMethod) {

        String orgId;
        // For org-mgt requests
        String[] requestUriParts = requestPath.split(URI_SPLITTER);
        orgId = Arrays.asList(requestUriParts)
                .get((Arrays.asList(requestUriParts).indexOf(ORGANIZATION_RESOURCE)) + 1);
        // For user-mgt requests
        return orgId;
    }

}
