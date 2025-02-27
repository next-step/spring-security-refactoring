package nextstep.security.config.annotation.configurer;

import nextstep.security.config.annotation.HttpSecurity;

public interface SecurityConfigurer {
    void init(HttpSecurity http);

    void configure(HttpSecurity http);
}
