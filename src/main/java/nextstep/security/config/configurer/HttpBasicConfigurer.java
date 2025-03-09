package nextstep.security.config.configurer;


import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.config.HttpSecurity;

import static nextstep.security.config.configuration.ConfigurationUtils.findSharedOrContextBean;

public class HttpBasicConfigurer implements SecurityConfigurer {
    @Override
    public void init(HttpSecurity http) {
    }

    @Override
    public void configure(HttpSecurity http) {
        final AuthenticationManager authenticationManager = findSharedOrContextBean(http, AuthenticationManager.class);
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager);
        http.addFilter(basicAuthenticationFilter);
    }
}
