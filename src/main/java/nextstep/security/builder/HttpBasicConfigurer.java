package nextstep.security.builder;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;

public class HttpBasicConfigurer implements SecurityConfigurer<HttpBasicConfigurer, HttpSecurity> {
    private AuthenticationManager authenticationManager;

    public HttpBasicConfigurer(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void init(HttpSecurity builder) {

    }

    @Override
    public void configure(HttpSecurity builder) {
        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager);
        builder.addFilter(basicAuthenticationFilter);
    }
}
