package nextstep.security.httpsecurity.configurer;

import nextstep.security.context.SecurityContextHolderFilter;
import nextstep.security.httpsecurity.HttpSecurity;

public class SecurityContextConfigurer implements SecurityConfigurer {
    @Override
    public void init(HttpSecurity http) {

    }

    @Override
    public void configure(HttpSecurity http) {
        SecurityContextHolderFilter securityContextHolderFilter = new SecurityContextHolderFilter();
        http.addFilter(securityContextHolderFilter);
    }
}
