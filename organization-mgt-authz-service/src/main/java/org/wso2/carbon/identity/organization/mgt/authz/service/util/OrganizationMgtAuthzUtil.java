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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.mgt.authz.service.internal.OrganizationMgtAuthzServiceHolder;
import org.wso2.carbon.identity.organization.mgt.authz.service.model.OrgResourceConfigKey;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

public class OrganizationMgtAuthzUtil {

    private static OrganizationMgtAuthzUtil organizationMgtAuthzUtil = new OrganizationMgtAuthzUtil();
    private Map<OrgResourceConfigKey, ResourceConfig> orgResourceConfigMap = new LinkedHashMap();
    private static final String ORG_MGT_CONFIG = "org-mgt.xml";
    private static final String ORG_MGT_ACCESS_CONTROL_CONFIG_ELEM = "OrgResourceAccessControl";
    private OMElement rootElement;
    private String defaultAccess;
    private boolean isScopeValidationEnabled = true;
    private static final Object lock = new Object();
    private static Log log = LogFactory.getLog(OrganizationMgtAuthzUtil.class);

    private OrganizationMgtAuthzUtil() {

        buildConfiguration();
    }

    public static OrganizationMgtAuthzUtil getInstance() {

        if (organizationMgtAuthzUtil == null) {
            synchronized (lock) {
                if (organizationMgtAuthzUtil == null) {
                    organizationMgtAuthzUtil = new OrganizationMgtAuthzUtil();
                }
            }
        }
        return organizationMgtAuthzUtil;
    }

    public ResourceConfig getSecuredConfig(OrgResourceConfigKey resourceConfigKey) {

        ResourceConfig resourceConfig = null;
        for (Map.Entry<OrgResourceConfigKey, ResourceConfig> entry : orgResourceConfigMap.entrySet()) {
            if (entry.getKey().equals(resourceConfigKey)) {
                resourceConfig = entry.getValue();
                break;
            }
        }
        return resourceConfig;
    }

    /**
     * Build rest api resource control config.
     */
    public void buildResourceAccessControlData() {

        OMElement orgResourceAccessControl = this.getConfigElement(ORG_MGT_ACCESS_CONTROL_CONFIG_ELEM);
        if (orgResourceAccessControl != null) {
            defaultAccess = orgResourceAccessControl.getAttributeValue(new QName(Constants.RESOURCE_DEFAULT_ACCESS));
            isScopeValidationEnabled = !Boolean.parseBoolean(orgResourceAccessControl
                    .getAttributeValue(new QName(Constants.RESOURCE_DISABLE_SCOPE_VALIDATION)));
            Iterator<OMElement> resources = orgResourceAccessControl.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.RESOURCE_ELE));
            if (resources != null) {

                while (resources.hasNext()) {
                    OMElement resource = resources.next();
                    ResourceConfig resourceConfig = new ResourceConfig();
                    String httpMethod = resource.getAttributeValue(
                            new QName(Constants.RESOURCE_HTTP_METHOD_ATTR));
                    String context = resource.getAttributeValue(new QName(Constants.RESOURCE_CONTEXT_ATTR));
                    String isSecured = resource.getAttributeValue(new QName(Constants.RESOURCE_SECURED_ATTR));
                    String isCrossTenantAllowed =
                            resource.getAttributeValue(new QName(Constants.RESOURCE_CROSS_TENANT_ATTR));
                    String allowedAuthHandlers =
                            resource.getAttributeValue(new QName(Constants.RESOURCE_ALLOWED_AUTH_HANDLERS));

                    StringBuilder permissionBuilder = new StringBuilder();
                    Iterator<OMElement> permissionsIterator = resource.getChildrenWithName(
                            new QName(Constants.RESOURCE_PERMISSION_ELE));
                    if (permissionsIterator != null) {
                        while (permissionsIterator.hasNext()) {
                            OMElement permissionElement = permissionsIterator.next();
                            String permission = permissionElement.getText();
                            if (StringUtils.isNotEmpty(permissionBuilder.toString()) &&
                                    StringUtils.isNotEmpty(permission)) {
                                permissionBuilder.append(",");
                            }
                            if (StringUtils.isNotEmpty(permission)) {
                                permissionBuilder.append(permission);
                            }
                        }
                    }

                    List<String> scopes = new ArrayList<>();
                    Iterator<OMElement> scopesIterator = resource.getChildrenWithName(
                            new QName(Constants.RESOURCE_SCOPE_ELE));
                    if (scopesIterator != null) {
                        while (scopesIterator.hasNext()) {
                            OMElement scopeElement = scopesIterator.next();
                            scopes.add(scopeElement.getText());
                        }
                    }

                    resourceConfig.setContext(context);
                    resourceConfig.setHttpMethod(httpMethod);
                    if (StringUtils.isNotEmpty(isSecured) && (Boolean.TRUE.toString().equals(isSecured) ||
                            Boolean.FALSE.toString().equals(isSecured))) {
                        resourceConfig.setIsSecured(Boolean.parseBoolean(isSecured));
                    }
                    if (StringUtils.isNotEmpty(isCrossTenantAllowed) &&
                            (Boolean.TRUE.toString().equals(isCrossTenantAllowed) ||
                                    Boolean.FALSE.toString().equals(isCrossTenantAllowed))) {
                        resourceConfig.setIsCrossTenantAllowed(Boolean.parseBoolean(isCrossTenantAllowed));
                    }

                    if (StringUtils.isBlank(allowedAuthHandlers)) {
                        // If 'allowed-auth-handlers' is not configured we consider all handlers are engaged.
                        allowedAuthHandlers = Constants.RESOURCE_ALLOWED_AUTH_HANDLERS_ALL;
                    }
                    resourceConfig.setAllowedAuthHandlers(allowedAuthHandlers);
                    resourceConfig.setPermissions(permissionBuilder.toString());
                    resourceConfig.setScopes(scopes);
                    orgResourceConfigMap.put(new OrgResourceConfigKey(context, httpMethod), resourceConfig);
                }
            }
        }
    }

    public void buildConfiguration() {

        InputStream inStream = null;
        StAXOMBuilder builder = null;

        try {
            File configXml = new File(IdentityUtil.getIdentityConfigDirPath(), ORG_MGT_CONFIG);
            if (configXml.exists()) {
                inStream = new FileInputStream(configXml);
            }
            if (inStream == null) {
                log.warn("org-mgt.xml configuration not found at: " + IdentityUtil.getIdentityConfigDirPath());
                return;
            }
            builder = new StAXOMBuilder(inStream);
            rootElement = builder.getDocumentElement();
            buildResourceAccessControlData();
        } catch (IOException | XMLStreamException e) {
            log.warn("Error occurred while building configuration from org-mgt.xml", e);
        } finally {
            try {
                if (inStream != null) {
                    inStream.close();
                }
            } catch (IOException e) {
                log.error("Error closing the input stream for org-mgt.xml", e);
            }
        }
    }

    private OMElement getConfigElement(String localPart) {

        return rootElement.getFirstChildWithName(new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE,
                localPart));
    }

    /**
     * Get the userstore manager for the user.
     *
     * @param user User.
     * @return Userstore manager.
     */
    public static UserStoreManager getUserStoreManager(User user) throws org.wso2.carbon.user.api.UserStoreException {

        RealmService realmService = OrganizationMgtAuthzServiceHolder.getInstance().getRealmService();
        UserRealm tenantUserRealm = realmService.getTenantUserRealm(IdentityTenantUtil.
                getTenantId(user.getTenantDomain()));
        if (IdentityUtil.getPrimaryDomainName().equals(user.getUserStoreDomain()) || user.getUserStoreDomain() == null) {
            return (UserStoreManager) tenantUserRealm.getUserStoreManager();
        }
        return ((UserStoreManager) tenantUserRealm.getUserStoreManager())
                .getSecondaryUserStoreManager(user.getUserStoreDomain());
    }

    public static UserStoreManager getUserStoreManager(int tenantId) throws UserStoreException {
        RealmService realmService = OrganizationMgtAuthzServiceHolder.getInstance().getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
        return (UserStoreManager) userRealm.getUserStoreManager();
    }
}
