package nextstep.security.config.configurer;

import nextstep.security.config.HttpSecurity;
import nextstep.security.context.SecurityContextHolderFilter;

public class SecurityContextConfigurer implements SecurityConfigurer {
    @Override
    public void init(HttpSecurity http) {
        SecurityContextHolderFilter securityContextHolderFilter = new SecurityContextHolderFilter();
        http.addFilter(securityContextHolderFilter);
    }

    @Override
    public void configure(HttpSecurity http) {
    }
}
