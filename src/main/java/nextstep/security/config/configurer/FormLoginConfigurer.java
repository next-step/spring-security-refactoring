package nextstep.security.config.configurer;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.config.HttpSecurity;

public class FormLoginConfigurer implements SecurityConfigurer {
    @Override
    public void init(final HttpSecurity http) {
    }

    @Override
    public void configure(final HttpSecurity http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter(authenticationManager);
        http.addFilter(filter);
    }
}
