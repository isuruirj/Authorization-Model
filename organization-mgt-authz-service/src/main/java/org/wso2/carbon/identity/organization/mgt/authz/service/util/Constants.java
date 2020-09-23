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
