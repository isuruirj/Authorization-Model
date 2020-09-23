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
///**
// * @scr.component name="org.wso2.carbon.identity.org.mgt.authz.service" immediate=true
// * @scr.reference name="user.realmservice.default"
// * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
// * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
// */
public class OrganizationMgtAuthzServiceComponent {

    private static final Log log = LogFactory.getLog(OrganizationMgtAuthzServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        cxt.getBundleContext()
                .registerService(AuthorizationHandler.class.getName(), new OrganizationMgtAuthzHandler(), null);
        log.info("======OrganizationMgtAuthzServiceComponent is activated========");
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
