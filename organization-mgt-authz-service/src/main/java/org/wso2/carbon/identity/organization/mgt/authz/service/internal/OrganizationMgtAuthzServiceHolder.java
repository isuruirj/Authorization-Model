package org.wso2.carbon.identity.organization.mgt.authz.service.internal;

import org.wso2.carbon.identity.authz.service.internal.AuthorizationServiceHolder;
import org.wso2.carbon.user.core.service.RealmService;

public class OrganizationMgtAuthzServiceHolder {

    private static OrganizationMgtAuthzServiceHolder organizationMgtAuthzServiceHolder = new OrganizationMgtAuthzServiceHolder();
    private RealmService realmService = null;

    private OrganizationMgtAuthzServiceHolder() {

    }

    public static OrganizationMgtAuthzServiceHolder getInstance() {
        return OrganizationMgtAuthzServiceHolder.organizationMgtAuthzServiceHolder;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

}
