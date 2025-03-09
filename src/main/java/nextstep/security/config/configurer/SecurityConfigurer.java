package nextstep.security.config.configurer;

import nextstep.security.config.HttpSecurity;

public interface SecurityConfigurer {

    void init(HttpSecurity http);

    void configure(HttpSecurity http);
}
