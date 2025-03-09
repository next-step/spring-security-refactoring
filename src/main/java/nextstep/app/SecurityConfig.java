package nextstep.app;

import nextstep.oauth2.OAuth2ClientProperties;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchyImpl;
import nextstep.security.authorization.SecuredMethodInterceptor;
import nextstep.security.config.Customizer;
import nextstep.security.config.HttpSecurity;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.config.annotation.EnableWebSecurity;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@Configuration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecuredMethodInterceptor securedMethodInterceptor() {
        return new SecuredMethodInterceptor();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.with()
                .role("ADMIN").implies("USER")
                .build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http
                .csrf(c -> c.ignoringRequestMatchers("/login"))
                .authorizeHttpRequests(
                        authorize -> authorize
                                .requestMatchers("/members").hasRole("ADMIN")
                                .requestMatchers("/members/me").hasRole("USER")
                                .anyRequest().permitAll())
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults())
                .build();
    }
}
