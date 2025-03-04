package nextstep.security.httpsecurity;

public interface SecurityConfigurer {
    void init(HttpSecurity http);

    void configure(HttpSecurity http);
}
