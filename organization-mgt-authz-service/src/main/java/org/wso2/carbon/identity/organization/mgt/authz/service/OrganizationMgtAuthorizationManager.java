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

package org.wso2.carbon.identity.organization.mgt.authz.service;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.organization.mgt.authz.service.dao.OrganizationMgtAuthzDAOImpl;
import org.wso2.carbon.user.api.UserStoreException;


/**
 * Manager for organization mgt related authorization.
 */
public class OrganizationMgtAuthorizationManager {

    private static OrganizationMgtAuthorizationManager organizationMgtAuthorizationManager =
            new OrganizationMgtAuthorizationManager();
    private static final Object lock = new Object();

    private OrganizationMgtAuthorizationManager() {

    }

    public static OrganizationMgtAuthorizationManager getInstance() {

        if (organizationMgtAuthorizationManager == null) {
            synchronized (lock) {
                if (organizationMgtAuthorizationManager == null) {
                    organizationMgtAuthorizationManager = new OrganizationMgtAuthorizationManager();
                }
            }
        }
        return organizationMgtAuthorizationManager;
    }

    /**
     * Check whether the user is authorized for the particular organization.
     *
     * @param user       User object.
     * @param resourceId Required permission.
     * @param action     Permission assignment action.
     * @param orgId      Organization id.
     * @param tenantId   Tenant id.
     * @return Whether the user is authorized or not.
     * @throws UserStoreException If error occurred while retrieving the userstore manager.
     */
    public boolean isUserAuthorized(User user, String resourceId, String action, String orgId, int tenantId)
            throws UserStoreException {

        OrganizationMgtAuthzDAOImpl organizationMgtAuthzDAOImpl = new OrganizationMgtAuthzDAOImpl();
        return organizationMgtAuthzDAOImpl.isUserAuthorized(user, resourceId, action, orgId, tenantId);
    }

    /**
     * Check whether the user has permission at least for one organization.
     *
     * @param user       User object.
     * @param resourceId Required permission.
     * @param action     Permission assignment action.
     * @param tenantId   Tenant id.
     * @return Whether the user is authorized or not.
     * @throws UserStoreException If error occurred while retrieving the userstore manager.
     */
    public boolean isUserAuthorized(User user, String resourceId, String action, int tenantId)
            throws UserStoreException {

        OrganizationMgtAuthzDAOImpl organizationMgtAuthzDAOImpl = new OrganizationMgtAuthzDAOImpl();
        return organizationMgtAuthzDAOImpl.isUserAuthorized(user, resourceId, action, tenantId);
    }
}
