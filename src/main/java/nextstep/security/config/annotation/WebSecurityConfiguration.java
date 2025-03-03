package nextstep.security.config.annotation;

import jakarta.servlet.Filter;
import nextstep.security.builder.Customizer;
import nextstep.security.builder.HttpSecurity;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration {

    @Bean
    public Filter springSecurityFilterChain(
            HttpSecurity http,
            List<SecurityFilterChain> securityFilterChains) {

        List<SecurityFilterChain> filterChains = new ArrayList<>(securityFilterChains);

        filterChains.add(http.authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .build());


        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        return filterChainProxy;
    }
}

