package org.wso2.carbon.identity.organization.mgt.authz.service;

import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.mgt.authz.service.internal.OrganizationMgtAuthzServiceHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;

import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.COUNT_COLUMN_NAME;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.GET_IS_USER_ALLOWED;
import static org.wso2.carbon.identity.organization.mgt.authz.service.util.Constants.PERMISSION_SPLITTER;

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

    public boolean isUserAuthorized(User user, String resourceId, String action, String orgId, int tenantId)
            throws UserStoreException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) getUserStoreManager(user);
        String userID = userStoreManager.getUser(null, user.getUserName()).getUserID();
        boolean isUserAllowed = false;
        String[] permissionParts = resourceId.split(PERMISSION_SPLITTER);
        String parentPermission =
                String.join(PERMISSION_SPLITTER, subArray(permissionParts, 0, permissionParts.length - 1));
        JdbcTemplate jdbcTemplate = getNewTemplate();
        try {
            int mappingsCount = jdbcTemplate.fetchSingleRecord(GET_IS_USER_ALLOWED,
                    (resultSet, rowNumber) ->
                            resultSet.getInt(COUNT_COLUMN_NAME),
                    preparedStatement -> {
                        int parameterIndex = 0;
                        preparedStatement.setString(++parameterIndex, orgId);
                        preparedStatement.setString(++parameterIndex, userID);
                        preparedStatement.setInt(++parameterIndex, tenantId);
                        preparedStatement.setInt(++parameterIndex, 3);
                        preparedStatement.setString(++parameterIndex, resourceId);
                        preparedStatement.setString(++parameterIndex, parentPermission);
                    });
            isUserAllowed = (mappingsCount > 0);
        } catch (DataAccessException e) {
            e.printStackTrace();
            // @TODO
        }
        return isUserAllowed;
    }

    /**
     * Get the userstore manager for the user.
     *
     * @param user User.
     * @return Userstore manager.
     */
    private UserStoreManager getUserStoreManager(User user) {

        UserStoreManager userStoreManager = null;
        RealmService realmService = OrganizationMgtAuthzServiceHolder.getInstance().getRealmService();
        try {
            UserRealm tenantUserRealm = realmService.getTenantUserRealm(IdentityTenantUtil.
                    getTenantId(user.getTenantDomain()));

            userStoreManager = (UserStoreManager) tenantUserRealm.getUserStoreManager();

        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            // @TODO
        }
        return userStoreManager;
    }

    public static JdbcTemplate getNewTemplate() {

        return new JdbcTemplate(IdentityDatabaseUtil.getDataSource());
    }

    public static <T> T[] subArray(T[] array, int beg, int end) {

        return Arrays.copyOfRange(array, beg, end);
    }
}
