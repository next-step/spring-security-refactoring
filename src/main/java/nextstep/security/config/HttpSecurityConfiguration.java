package nextstep.security.config;

import nextstep.oauth2.registration.ClientRegistrationRepository;
import nextstep.security.access.hierarchicalroles.NullRoleHierarchy;
import nextstep.security.access.hierarchicalroles.RoleHierarchy;
import nextstep.security.authentication.AuthenticationManager;
import nextstep.security.builder.HttpSecurity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class HttpSecurityConfiguration {

    @Bean
    @Scope("prototype")
    public HttpSecurity httpSecurity(
            AuthenticationManager authenticationManager
            , ClientRegistrationRepository clientRegistrationRepository
            , @Autowired(required = false) RoleHierarchy roleHierarchy
    ) {

        if (roleHierarchy == null) {
            roleHierarchy = new NullRoleHierarchy();
        }

        HttpSecurity httpSecurity = new HttpSecurity(authenticationManager);
        httpSecurity.setSharedObject(RoleHierarchy.class, roleHierarchy);
        httpSecurity.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);

        return httpSecurity;
    }
}
