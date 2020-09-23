package org.wso2.carbon.identity.organization.mgt.authz.valve.internal;

import org.wso2.carbon.identity.authz.service.AuthorizationManager;

import java.util.ArrayList;
import java.util.List;

public class OrganizationMgtAuthzValveServiceHolder {

    private static OrganizationMgtAuthzValveServiceHolder organizationMgtAuthzValveServiceHolder = new OrganizationMgtAuthzValveServiceHolder();
    private List<AuthorizationManager> authorizationManagerList = new ArrayList<AuthorizationManager>();

    private OrganizationMgtAuthzValveServiceHolder() {

    }

    public static OrganizationMgtAuthzValveServiceHolder getInstance() {
        return OrganizationMgtAuthzValveServiceHolder.organizationMgtAuthzValveServiceHolder;
    }

    public List<AuthorizationManager> getAuthorizationManagerList() {
        return authorizationManagerList;
    }

    public void setAuthorizationManagerList(List<AuthorizationManager> authorizationManagerList) {

        this.authorizationManagerList = authorizationManagerList;
    }
}
