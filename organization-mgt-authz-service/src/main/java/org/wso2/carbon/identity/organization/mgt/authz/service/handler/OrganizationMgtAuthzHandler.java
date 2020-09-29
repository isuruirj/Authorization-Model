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
import org.wso2.carbon.identity.organization.mgt.authz.service.internal.OrganizationMgtAuthzServiceHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.AND;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.CONDITION_SEPARATOR;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.EQ;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.FILTER_START;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.HTTP_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_ID_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_ID_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_NAME_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_RESOURCE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.QUERY_STRING_SEPARATOR;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_GROUPS_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_USERS_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_USER_REQUESTS;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_URLS_WITH_ORG_ID;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.SCIM_USERS_RESOURCE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.URI_SPLITTER;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.OrganizationMgtAuthzUtil.getUserStoreManager;

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
            String requestUri = ((OrgMgtAuthorizationContext) authorizationContext).getRequestUri();
            User user = authorizationContext.getUser();
            String userDomain = user.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(userDomain);
            String permissionString = authorizationContext.getPermissionString();
            String[] allowedScopes = authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES) == null ? null :
                    (String[]) authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES);
            boolean validateScope = authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE) == null ? false :
                    (Boolean) authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE);

            if (!canHandle(requestUri, authorizationContext.getHttpMethods(),
                    ((OrgMgtAuthorizationContext) authorizationContext).getQueryString())) {
                // Need to handle differently. For now grant access.
                // TODO
                authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            } else {
                if ((Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET, requestUri) &&
                        HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods()))) {
                    // Check whether the user has the permission for at least one organization.
                    validatePermissions(authorizationResult, user, permissionString, tenantId);
                } else {
                    // Request can be handled in this handler.
                    String orgId = retrieveOrganizationId(requestUri, authorizationContext.getHttpMethods(), tenantId);
                    if (orgId != null) {
                        if (StringUtils.isNotBlank(permissionString)) {
                            validatePermissions(authorizationResult, user, permissionString, orgId, tenantId);
                        }
                    } else {
                        String errorMessage = "Error occurred while retrieving the organization id.";
                        log.error(errorMessage);
                        throw new AuthzServiceServerException(errorMessage);
                    }
                }

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

    private void validatePermissions(AuthorizationResult authorizationResult, User user, String permissionString,
                                     int tenantId)
            throws org.wso2.carbon.user.api.UserStoreException {

        if (RESOURCE_PERMISSION_NONE.equalsIgnoreCase(permissionString)) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            return;
        }
        boolean isUserAuthorized = OrganizationMgtAuthorizationManager.getInstance()
                .isUserAuthorized(user, permissionString, CarbonConstants.UI_PERMISSION_ACTION, tenantId);
        if (isUserAuthorized) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
        }
    }

    private String retrieveOrganizationId(String requestPath, String getHttpMethod, int tenantId)
            throws UserStoreException {

        String orgId = null;
        if (Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestPath)) {
            String[] requestUriParts = requestPath.split(URI_SPLITTER);
            orgId = Arrays.asList(requestUriParts)
                    .get((Arrays.asList(requestUriParts).indexOf(ORGANIZATION_RESOURCE)) + 1);
        } else if (Pattern.matches(REGEX_FOR_SCIM_USER_REQUESTS, requestPath)) {
            String[] requestUriParts = requestPath.split(URI_SPLITTER);
            String userId = Arrays.asList(requestUriParts)
                    .get((Arrays.asList(requestUriParts).indexOf(SCIM_USERS_RESOURCE)) + 1);
            UserStoreManager carbonUM = getUserStoreManager(tenantId);
            if (carbonUM == null) {
                throw new UserStoreException("Error while retrieving userstore manager for tenant: " + tenantId);
            }
            orgId = ((AbstractUserStoreManager) carbonUM)
                    .getUserClaimValueWithID(userId, ORGANIZATION_ID_DEFAULT_CLAIM_URI, null);
        }
        return orgId;
    }

    private boolean canHandle(String requestPath, String getHttpMethod, String queryParams) {

        boolean canHandle = false;
        if (Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestPath) ||
                Pattern.matches(REGEX_FOR_SCIM_USER_REQUESTS, requestPath) ||
                (Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET, requestPath) && HTTP_GET.equalsIgnoreCase(getHttpMethod))) {
            canHandle = true;
        }
        if (Pattern.matches(REGEX_FOR_SCIM_USERS_GET, requestPath) && queryParams != null) {
            String[] queryParamsParts = queryParams.split(QUERY_STRING_SEPARATOR);
            for (String param : Arrays.asList(queryParamsParts)) {
                if (param.startsWith(FILTER_START)) {
                    String filter = param;
                    String[] filterConditions = filter.split(AND);
                    StringBuilder filterWithOrgId =
                            new StringBuilder(ORGANIZATION_ID_URI).append(CONDITION_SEPARATOR).append(EQ)
                                    .append(CONDITION_SEPARATOR);
                    StringBuilder filterWithOrgName =
                            new StringBuilder(ORGANIZATION_NAME_URI).append(CONDITION_SEPARATOR).append(EQ)
                                    .append(CONDITION_SEPARATOR);
                }
            }
        }

        return canHandle;
    }

}
