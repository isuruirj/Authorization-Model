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
import org.wso2.carbon.identity.organization.mgt.authz.service.dao.OrganizationMgtAuthzDAOImpl;
import org.wso2.carbon.identity.organization.mgt.authz.service.internal.OrganizationMgtAuthzServiceHolder;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationMgtDao;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationMgtDaoImpl;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Arrays;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ANY_ORG;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.CONDITION_SEPARATOR;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.FILTER_START;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.HTTP_DELETE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.HTTP_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.HTTP_PATCH;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.HTTP_POST;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_ID_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_ID_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_MGT_ADMIN_PERMISSION;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_NAME_URI;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.ORGANIZATION_RESOURCE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.QUERY_STRING_SEPARATOR;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_ADMIN_ROLE_ASSIGNMENT_REVOKE_AND_UPDATE;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_ADMIN_ROLE_MEMBERS_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_GET_ORG_BY_ORG_ID;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_ORG_SEARCH;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_GROUPS_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_GROUPS_GET_BY_ID;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_USERS_GET;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_SCIM_USER_REQUESTS;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_FOR_URLS_WITH_ORG_ID;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.REGEX_SCIM_USERS_FILTER_WITH_ORG;
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

        // If context not found in org-mgt, use the default authorization.
        if (!(authorizationContext instanceof OrgMgtAuthorizationContext)) {
            return super.handleAuthorization(authorizationContext);
        }
        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        try {
            String requestUri = ((OrgMgtAuthorizationContext) authorizationContext).getRequestUri();
            String queryString = ((OrgMgtAuthorizationContext) authorizationContext).getQueryString();
            User user = authorizationContext.getUser();
            String userDomain = user.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(userDomain);
            String permissionString = authorizationContext.getPermissionString();
            String[] allowedScopes = authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES) == null ? null :
                    (String[]) authorizationContext.getParameter(OAUTH2_ALLOWED_SCOPES);
            boolean validateScope = authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE) == null ? false :
                    (Boolean) authorizationContext.getParameter(OAUTH2_VALIDATE_SCOPE);
            String canHandle = canHandle(requestUri, authorizationContext.getHttpMethods(), queryString);
            if (StringUtils.equals("false", canHandle)) {
                // Pass through from the valve. For now grant access. These requests will be handled in the backend.
                authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            } else if (StringUtils.equals("root", canHandle)) {
                // Retrieve the organizationId of ROOT org.
                OrganizationMgtAuthzDAOImpl organizationMgtAuthzDAOImpl = new OrganizationMgtAuthzDAOImpl();
                String rootOrgId = organizationMgtAuthzDAOImpl.getRootOrgId("ROOT", tenantId);
                validatePermissions(authorizationResult, user, permissionString, rootOrgId, tenantId);
            } else {
                if ((Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET, requestUri) &&
                        HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods())) ||
                        (Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET_BY_ID, requestUri) &&
                                HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods())) ||
                        (Pattern.matches(REGEX_FOR_SCIM_USERS_GET, requestUri) &&
                                HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods()) &&
                                !(queryString != null &&
                                        Pattern.matches(REGEX_SCIM_USERS_FILTER_WITH_ORG, queryString))) ||
                        (Pattern.matches(REGEX_FOR_ORG_SEARCH, requestUri) &&
                                !Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestUri) &&
                                HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods()))) {
                    /*
                     Check whether the user has the organizationmgt/admin permission in the default model or
                     relevant permission for at least one organization.
                     - GET /scim2/Users without organization filtering
                     - GET /scim2/Groups
                     - GET /scim2/Groups/{group-id}
                     - GET /organizations
                     */
                    validatePermissionsInDefaultPermissionTree(authorizationResult, user,
                            ORGANIZATION_MGT_ADMIN_PERMISSION, tenantId);
                    if (!(AuthorizationStatus.GRANT).equals(authorizationResult.getAuthorizationStatus())) {
                        validatePermissions(authorizationResult, user, permissionString, ANY_ORG, tenantId);
                    }
                } else {
                    // Request can be handled in this handler.
                    String orgId = retrieveOrganizationId(requestUri, authorizationContext.getHttpMethods(),
                            queryString, tenantId);
                    if (orgId != null) {
                        if (StringUtils.isNotBlank(permissionString)) {
                            validatePermissions(authorizationResult, user, permissionString, orgId, tenantId);
                            if (!(AuthorizationStatus.GRANT).equals(authorizationResult.getAuthorizationStatus()) &&
                                    ((Pattern.matches(REGEX_FOR_GET_ORG_BY_ORG_ID, requestUri) &&
                                            HTTP_GET.equalsIgnoreCase(authorizationContext.getHttpMethods())) ||
                                            (Pattern.matches(REGEX_FOR_ADMIN_ROLE_ASSIGNMENT_REVOKE_AND_UPDATE,
                                                    requestUri) &&
                                                    (HTTP_POST
                                                            .equalsIgnoreCase(authorizationContext.getHttpMethods()) ||
                                                            HTTP_DELETE.equalsIgnoreCase(
                                                                    authorizationContext.getHttpMethods()) || HTTP_PATCH
                                                            .equalsIgnoreCase(
                                                                    authorizationContext.getHttpMethods()))) ||
                                            (Pattern.matches(REGEX_FOR_ADMIN_ROLE_MEMBERS_GET, requestUri) &&
                                                    HTTP_GET.equalsIgnoreCase(
                                                            authorizationContext.getHttpMethods())) ||
                                            (Pattern.matches(REGEX_FOR_SCIM_USER_REQUESTS, requestUri) &&
                                                    HTTP_GET.equalsIgnoreCase(
                                                            authorizationContext.getHttpMethods())))) {
                                /*
                                Check whether the user has the organizationmgt/admin permission in the default model,
                                if the request is
                                - GET /organizations/{organization-id}
                                - GET /scim2/Users/{user-id}
                                - POST /organizations/{organization-id}/roles
                                - DELETE /organizations/{organization-id}/roles/{role-id}/users/{user-id}
                                - PATCH /organizations/{organization-id}/roles/{role-id}/users/{user-id}
                                - GET /organizations/{organization-id}/roles/{role-id}/users
                                 */
                                validatePermissionsInDefaultPermissionTree(authorizationResult, user,
                                        ORGANIZATION_MGT_ADMIN_PERMISSION, tenantId);
                            }
                        }
                    } else {
                        String errorMessage = "Error occurred while retrieving the organization id.";
                        log.error(errorMessage);
                        throw new AuthzServiceServerException(errorMessage);
                    }
                }
            }
        } catch (UserStoreException | OrganizationManagementException e) {
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
        boolean isUserAuthorized;
        if(StringUtils.equals(ANY_ORG,orgId)) {
            isUserAuthorized = OrganizationMgtAuthorizationManager.getInstance()
                    .isUserAuthorized(user, permissionString, CarbonConstants.UI_PERMISSION_ACTION, tenantId);
        } else {
            isUserAuthorized = OrganizationMgtAuthorizationManager.getInstance()
                    .isUserAuthorized(user, permissionString, CarbonConstants.UI_PERMISSION_ACTION, orgId, tenantId);
        }
        if (isUserAuthorized) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
        }
    }

    private void validatePermissionsInDefaultPermissionTree(AuthorizationResult authorizationResult, User user,
                                                            String permissionString, int tenantId)
            throws UserStoreException {

        if (RESOURCE_PERMISSION_NONE.equalsIgnoreCase(permissionString)) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
            return;
        }
        RealmService realmService = OrganizationMgtAuthzServiceHolder.getInstance().getRealmService();
        UserRealm tenantUserRealm = realmService.getTenantUserRealm(tenantId);
        AuthorizationManager authorizationManager = tenantUserRealm.getAuthorizationManager();
        boolean isUserAuthorized =
                authorizationManager.isUserAuthorized(UserCoreUtil.addDomainToName(user.getUserName(),
                        user.getUserStoreDomain()), permissionString, CarbonConstants.UI_PERMISSION_ACTION);
        if (isUserAuthorized) {
            authorizationResult.setAuthorizationStatus(AuthorizationStatus.GRANT);
        }
    }

    private String retrieveOrganizationId(String requestPath, String getHttpMethod, String queryString, int tenantId)
            throws UserStoreException, OrganizationManagementException {

        String orgId = null;
        UserStoreManager carbonUM = getUserStoreManager(tenantId);
        if (carbonUM == null) {
            throw new UserStoreException("Error while retrieving userstore manager for tenant: " + tenantId);
        }
        if (Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestPath)) {
            String[] requestUriParts = requestPath.split(URI_SPLITTER);
            orgId = Arrays.asList(requestUriParts)
                    .get((Arrays.asList(requestUriParts).indexOf(ORGANIZATION_RESOURCE)) + 1);
        } else if (Pattern.matches(REGEX_FOR_SCIM_USER_REQUESTS, requestPath)) {
            String[] requestUriParts = requestPath.split(URI_SPLITTER);
            String userId = Arrays.asList(requestUriParts)
                    .get((Arrays.asList(requestUriParts).indexOf(SCIM_USERS_RESOURCE)) + 1);
            orgId = ((AbstractUserStoreManager) carbonUM)
                    .getUserClaimValueWithID(userId, ORGANIZATION_ID_DEFAULT_CLAIM_URI, null);
        } else if (Pattern.matches(REGEX_FOR_SCIM_USERS_GET, requestPath) &&
                Pattern.matches(REGEX_SCIM_USERS_FILTER_WITH_ORG, queryString)) {
            // Assume logical condition "AND" and expression operator "EQ" is supported.
            String[] queryStringParts = queryString.split(QUERY_STRING_SEPARATOR);
            String filter = StringUtils.EMPTY;
            for (String queryStringPart : queryStringParts) {
                if (queryStringPart.contains(FILTER_START)) {
                    filter = queryStringPart;
                    break;
                }
            }
            String[] filterParts = filter.replace(FILTER_START, "").split(CONDITION_SEPARATOR);
            if (Arrays.asList(filterParts).contains(ORGANIZATION_ID_URI)) {
                orgId = Arrays.asList(filterParts)
                        .get(Arrays.asList(filterParts).indexOf(ORGANIZATION_ID_URI) + 2);
            } else if (Arrays.asList(filterParts).contains(ORGANIZATION_NAME_URI)) {
                String orgName = Arrays.asList(filterParts)
                        .get(Arrays.asList(filterParts).indexOf(ORGANIZATION_NAME_URI) + 2);
                OrganizationMgtDao organizationMgtDao = new OrganizationMgtDaoImpl();
                orgId = organizationMgtDao.getOrganizationIdByName(tenantId, orgName);
            }
        }
        return orgId;
    }

    private String canHandle(String requestPath, String getHttpMethod, String queryParams) {

        String canHandle = "false";
        if (Pattern.matches(REGEX_FOR_URLS_WITH_ORG_ID, requestPath) ||
                Pattern.matches(REGEX_FOR_SCIM_USER_REQUESTS, requestPath) ||
                (Pattern.matches(REGEX_FOR_ORG_SEARCH, requestPath) && HTTP_GET.equalsIgnoreCase(getHttpMethod)) ||
                (Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET, requestPath) && HTTP_GET.equalsIgnoreCase(getHttpMethod)) ||
                (Pattern.matches(REGEX_FOR_SCIM_GROUPS_GET_BY_ID, requestPath) &&
                        HTTP_GET.equalsIgnoreCase(getHttpMethod)) ||
                (Pattern.matches(REGEX_FOR_SCIM_USERS_GET, requestPath) && HTTP_GET.equalsIgnoreCase(getHttpMethod))) {
            canHandle = "true";
        }
        return canHandle;
    }

}
