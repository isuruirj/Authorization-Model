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

public class Constants {

    public static final String GET_IS_USER_ALLOWED = "SELECT COUNT(1) FROM ORG_AUTHZ_VIEW\n" +
            "WHERE ORG_ID = ? AND UM_USER_ID = ? AND UM_TENANT_ID = ? AND UM_DOMAIN_ID = ?" +
            " AND (UM_RESOURCE_ID = ? OR UM_RESOURCE_ID = ?)";
    public static final String AND = " AND ";
    public static final String OR = " OR ";
    public static final String PERMISSION_REQUIRED = "UM_RESOURCE_ID = ?";
    public static final String COUNT_COLUMN_NAME = "COUNT(1)";

    public static final String PERMISSION_SPLITTER = "/";
    public static final String URI_SPLITTER = "/";
    public static final String ORGANIZATION_RESOURCE = "organizations";
    public static final String REGEX_FOR_URLS_WITH_ORG_ID =
            "^(.)*(/api/identity/organization-mgt/v1.0/organizations/)[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(.)*$";
    public static final String ORG_ID_REGEX = "[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}";
}
