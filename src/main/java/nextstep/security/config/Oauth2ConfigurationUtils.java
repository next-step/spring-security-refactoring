package nextstep.security.config;

import org.springframework.context.ApplicationContext;

public class Oauth2ConfigurationUtils {
    public static <T> T findSharedOrContextBean(HttpSecurity http, Class<T> beanType) {
        final T sharedObject = http.getSharedObject(beanType);
        if (sharedObject != null) {
            return sharedObject;
        }

        return http.getSharedObject(ApplicationContext.class).getBean(beanType);
    }
}
