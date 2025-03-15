package nextstep.app;

import nextstep.autoconfigure.Customizer;
import nextstep.autoconfigure.HttpSecurity;
import nextstep.oauth2.OAuth2ClientProperties;
import nextstep.oauth2.authentication.OAuth2LoginAuthenticationProvider;
import nextstep.oauth2.userinfo.OAuth2UserService;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchyImpl;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.authentication.DaoAuthenticationProvider;
import nextstep.security.authentication.ProviderManager;
import nextstep.security.authorization.SecuredMethodInterceptor;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.userdetails.UserDetailsService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import java.util.List;


@Configuration
@EnableAspectJAutoProxy
@EnableConfigurationProperties(OAuth2ClientProperties.class)
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final OAuth2UserService oAuth2UserService;
    private final OAuth2ClientProperties oAuth2ClientProperties;

    public SecurityConfig(UserDetailsService userDetailsService, OAuth2UserService oAuth2UserService, OAuth2ClientProperties oAuth2ClientProperties) {
        this.userDetailsService = userDetailsService;
        this.oAuth2UserService = oAuth2UserService;
        this.oAuth2ClientProperties = oAuth2ClientProperties;
    }


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
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(
                new DaoAuthenticationProvider(userDetailsService),
                new OAuth2LoginAuthenticationProvider(oAuth2UserService)));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        return http
                .securityContext(context ->
                        context.securityContextRepository(new HttpSessionSecurityContextRepository())
                )
                .csrf(csrf -> {
                    csrf.ignoringRequestMatchers("/login");
                })
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/members").hasAuthority("ADMIN")
                                .requestMatchers("/search").hasAuthority("ADMIN")
                                .requestMatchers("/members/me").authenticated()
                                .anyRequest().permitAll())
                .formLogin(formLogin ->
                        formLogin.loginPage("/login").permitAll())
                .httpBasic(Customizer.withDefaults())
                .oAuth2Login(Customizer.withDefaults())
                .build();
    }

}

