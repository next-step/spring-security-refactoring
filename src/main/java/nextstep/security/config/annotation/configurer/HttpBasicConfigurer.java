package nextstep.security.config.annotation.configurer;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;
import nextstep.security.config.annotation.HttpSecurity;

public class HttpBasicConfigurer implements SecurityConfigurer {
    @Override
    public void init(HttpSecurity http) {
    }

    @Override
    public void configure(HttpSecurity http) {
        var authenticationManager = http.getSharedObject(AuthenticationManager.class);
        var basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager);
        http.addFilter(basicAuthenticationFilter);
    }
}
