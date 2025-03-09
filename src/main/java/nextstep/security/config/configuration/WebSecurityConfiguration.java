package nextstep.security.config.configuration;

import jakarta.servlet.Filter;
import nextstep.security.config.Customizer;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.HttpSecurity;
import nextstep.security.config.SecurityFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration {

    public static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";

    private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();

    @Autowired(required = false)
    private HttpSecurity httpSecurity;

    @Autowired(required = false)
    void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
        this.securityFilterChains = securityFilterChains;
    }

    // springSecurityFilterChain이름의 빈으로 FilterChainProxy을 생성
    @Bean(name = DEFAULT_FILTER_NAME)
    public Filter springSecurityFilterChain() {
        boolean hasFilterChain = !this.securityFilterChains.isEmpty();

        if (!hasFilterChain) {
            this.httpSecurity.authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll());
            this.httpSecurity.formLogin(Customizer.withDefaults());
            this.httpSecurity.httpBasic(Customizer.withDefaults());
            SecurityFilterChain filterChain = this.httpSecurity.build();
            securityFilterChains.add(filterChain);
        }

        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        return filterChainProxy;
    }
}