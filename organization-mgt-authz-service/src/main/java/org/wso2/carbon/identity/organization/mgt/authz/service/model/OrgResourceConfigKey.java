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
