package org.wso2.carbon.identity.organization.mgt.authz.valve.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.authz.service.AuthorizationManager;
import org.wso2.carbon.identity.core.handler.HandlerComparator;

import java.util.List;

import static java.util.Collections.sort;

@Component(
        name = "org.wso2.carbon.identity.organization.mgt.authz.valve",
        immediate = true)
public class OrganizationMgtAuthzValveServiceComponent {

    private static final Log log = LogFactory.getLog(OrganizationMgtAuthzValveServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {
        if (log.isDebugEnabled())
            log.debug("OrganizationMgtAuthzValveServiceComponent is activated");
        log.info("=========================OrganizationMgtAuthzValveServiceComponent");
    }

    @Reference(
            name = "org.wso2.carbon.identity.authz.service.manager.consume",
            service = org.wso2.carbon.identity.authz.service.AuthorizationManager.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthorizationManager")
    protected void setAuthorizationManager(AuthorizationManager authorizationManager) {
        if (log.isDebugEnabled()) {
            log.debug("AuthorizationManager acquired");
        }
        List<AuthorizationManager>
                authorizationManagerList = OrganizationMgtAuthzValveServiceHolder.getInstance().getAuthorizationManagerList();
        authorizationManagerList.add(authorizationManager);
        sort(authorizationManagerList, new HandlerComparator());
    }

    protected void unsetAuthorizationManager(AuthorizationManager authorizationManager) {
        List<AuthorizationManager> authorizationManagerList = OrganizationMgtAuthzValveServiceHolder.getInstance().getAuthorizationManagerList();
        authorizationManagerList.remove(authorizationManager);
    }
}
