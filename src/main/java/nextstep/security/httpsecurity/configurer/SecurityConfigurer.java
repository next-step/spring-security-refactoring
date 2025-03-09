package nextstep.security.httpsecurity.configurer;

import nextstep.security.httpsecurity.HttpSecurity;

public interface SecurityConfigurer {
    void init(HttpSecurity http);

    void configure(HttpSecurity http);
}
