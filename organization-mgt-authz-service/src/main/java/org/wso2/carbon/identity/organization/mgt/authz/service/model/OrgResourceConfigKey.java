package org.wso2.carbon.identity.organization.mgt.authz.service.model;

import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OrgResourceConfigKey {

    private String contextPath;
    private String httpMethod;
    private Pattern pattern;

    public OrgResourceConfigKey(String contextPath, String httpMethod) {

        this.contextPath = contextPath;
        this.httpMethod = httpMethod;
        this.pattern = Pattern.compile(contextPath);
    }

    public String getContextPath() {

        return contextPath;
    }

    public void setContextPath(String contextPath) {

        this.contextPath = contextPath;
    }

    public String getHttpMethod() {

        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {

        this.httpMethod = httpMethod;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        OrgResourceConfigKey that = (OrgResourceConfigKey) o;
        Matcher matcher = pattern.matcher(that.contextPath);
        if (!matcher.matches()) {
            return false;
        }

        if (httpMethod.equalsIgnoreCase("all")) {
            return true;
        }
        return httpMethod.contains(that.httpMethod);
    }

    @Override
    public int hashCode() {

        int result = contextPath.hashCode();
        result = 31 * result + httpMethod.hashCode();
        return result;
    }
}
