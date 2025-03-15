package nextstep.autoconfigure;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.BasicAuthenticationFilter;

public class HttpBasicConfigurer extends AbstractFilterConfigurer<HttpBasicConfigurer> {
    @Override
    public void init(final HttpSecurity httpSecurity) {

    }

    @Override
    protected void doConfigure(final HttpSecurity httpSecurity) {
        var filter = new BasicAuthenticationFilter(httpSecurity.getSharedObject(AuthenticationManager.class));
        httpSecurity.addFilter(filter);
    }

}
