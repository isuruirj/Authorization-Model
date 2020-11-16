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

package org.wso2.carbon.identity.organization.mgt.authz.service.util;

/**
 * Constants related to organization mgt authorization service and manager.
 */
public class Constants {

    // SQL Constants.
    public static final String GET_IS_USER_ALLOWED = "SELECT COUNT(1) FROM ORG_AUTHZ_VIEW\n" +
            "WHERE ORG_ID = ? AND UM_USER_ID = ? AND UM_TENANT_ID = ? AND UM_DOMAIN_ID = ?";
    public static final String GET_IS_USER_ALLOWED_AT_LEAST_FOR_ONE_ORG = "SELECT COUNT(1) FROM ORG_AUTHZ_VIEW\n" +
            "WHERE UM_USER_ID = ? AND UM_TENANT_ID = ? AND UM_DOMAIN_ID = ?";
    public static final String GET_ROOT_ORG_ID =   "SELECT\n" +
            "    DISTINCT ID\n" +
            "FROM\n" +
            "    UM_ORG\n" +
            "WHERE\n" +
            "    NAME = ? AND TENANT_ID = ?";

    public static final String AND = " AND ";
    public static final String OR = " OR ";
    public static final String PERMISSION_REQUIRED = "UM_RESOURCE_ID = ?";
    public static final String COUNT_COLUMN_NAME = "COUNT(1)";
    public static final String VIEW_ID = "ID";

    public static final String PERMISSION_SPLITTER = "/";
    public static final String URI_SPLITTER = "/";
    public static final String ORGANIZATION_RESOURCE = "organizations";
    public static final String SCIM_USERS_RESOURCE = "Users";
    public static final String REGEX_FOR_GET_USER_BY_ORG_ID =
            "^(.)*(/api/identity/organization-mgt/v1.0/organizations/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}$";
    public static final String REGEX_FOR_URLS_WITH_ORG_ID =
            "^(.)*(/api/identity/organization-mgt/v1.0/organizations/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(.)*$";
    public static final String REGEX_FOR_ROLE_ASSIGNMENT =
            "^(.)*(/api/identity/organization-mgt/v1.0/organizations/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(/roles)(.)*$";
    public static final String REGEX_FOR_ORG_SEARCH = "^(.)*(/api/identity/organization-mgt/v1.0/organizations)(.)*$";
    public static final String ORG_ID_REGEX = "[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}";
    public static final String REGEX_FOR_SCIM_USER_REQUESTS =
            "^(.)*(/scim2/Users/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(.)*$";
    public static final String ORGANIZATION_ID_DEFAULT_CLAIM_URI = "http://wso2.org/claims/organizationId";
    public static final String REGEX_FOR_SCIM_GROUPS_GET = "(.*)/scim2/Groups";
    public static final String REGEX_FOR_SCIM_USERS_GET = "(.*)/scim2/Users(.*)";
    public static final String HTTP_GET = "GET";
    public static final String HTTP_POST = "POST";
    public static final String ANY_ORG = "ANY";
    public static final String QUERY_STRING_SEPARATOR = "&";
    public static final String FILTER_START = "filter=";
    public static final String ORGANIZATION_ID_URI =
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.organization.id";
    public static final String ORGANIZATION_NAME_URI =
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.organization.name";
    public static final String EQ = "eq";
    public static final String CONDITION_SEPARATOR = "\\+";
    public static final String REGEX_SCIM_USERS_FILTER_WITH_ORG =
            "^(.)*(filter=)(.)*(" + ORGANIZATION_ID_URI + "|" + ORGANIZATION_NAME_URI + ")(.)*$";

    public static final String ERROR_RETRIEVING_ROOT_ID = "Error while retrieving the root organization id.";

    public static final String ORGANIZATION_MGT_ADMIN_PERMISSION = "/permission/admin/manage/identity/organizationmgt/admin";
}
