package nextstep.security.configurer;

import nextstep.security.HttpSecurity;

public interface SecurityConfigurer {
    void init(HttpSecurity http);

    void configure(HttpSecurity http);
}
