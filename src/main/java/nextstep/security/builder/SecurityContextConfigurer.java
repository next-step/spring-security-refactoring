package nextstep.security.builder;

import nextstep.security.context.SecurityContextHolderFilter;

public class SecurityContextConfigurer implements SecurityConfigurer<SecurityContextHolderFilter, HttpSecurity> {
    @Override
    public void init(HttpSecurity http) {

    }

    @Override
    public void configure(HttpSecurity http) {
        SecurityContextHolderFilter securityContextHolderFilter = new SecurityContextHolderFilter();
        http.addFilter(securityContextHolderFilter);
    }
}
