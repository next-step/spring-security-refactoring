package nextstep.autoconfigure;

public interface SecurityConfigurer {

    void init(HttpSecurity httpSecurity);

    void configure(HttpSecurity httpSecurity);

}
