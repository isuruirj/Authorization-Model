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

package org.wso2.carbon.identity.organization.mgt.authz.service.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.organization.mgt.authz.service.handler.OrganizationMgtAuthzHandler;
import org.wso2.carbon.identity.organization.mgt.authz.service.util.OrganizationMgtAuthzUtil;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "org.wso2.carbon.identity.org.mgt.authz.service",
        immediate = true)
public class OrganizationMgtAuthzServiceComponent {

    private static final Log log = LogFactory.getLog(OrganizationMgtAuthzServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        cxt.getBundleContext()
                .registerService(AuthorizationHandler.class.getName(), new OrganizationMgtAuthzHandler(), null);
        // Build the configuration file.
        OrganizationMgtAuthzUtil.getInstance();
        if (log.isDebugEnabled()) {
            log.debug("OrganizationMgtAuthzServiceComponent is activated.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext cxt) {

        if (log.isDebugEnabled()) {
            log.debug("OrganizationMgtAuthzServiceComponent bundle is deactivated.");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("RealmService acquired");
        }
        OrganizationMgtAuthzServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        setRealmService(null);
    }

}
