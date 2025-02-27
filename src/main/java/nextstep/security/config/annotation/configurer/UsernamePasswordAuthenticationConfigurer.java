package nextstep.security.config.annotation.configurer;

import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.UsernamePasswordAuthenticationFilter;
import nextstep.security.config.annotation.HttpSecurity;

public class UsernamePasswordAuthenticationConfigurer implements SecurityConfigurer {

    @Override
    public void init(HttpSecurity http) {
        // 다른 요소가 필요없음
    }

    @Override
    public void configure(HttpSecurity http) {
        var authenticationManager = http.getSharedObject(AuthenticationManager.class);
        var usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter(authenticationManager);
        http.addFilter(usernamePasswordAuthenticationFilter);
    }

}
