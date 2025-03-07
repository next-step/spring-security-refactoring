package nextstep.security.config.configuration;

import nextstep.security.config.HttpSecurity;
import org.springframework.context.ApplicationContext;

public class ConfigurationUtils {
    public static <T> T findSharedOrContextBean(HttpSecurity http, Class<T> beanType) {
        final T sharedObject = http.getSharedObject(beanType);
        if (sharedObject != null) {
            return sharedObject;
        }

        return http.getSharedObject(ApplicationContext.class).getBean(beanType);
    }
}
