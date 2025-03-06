package nextstep.security.autoconfigure;

import nextstep.oauth2.registration.ClientRegistration;
import nextstep.security.httpsecurity.EnableWebSecurity;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration(before = SecurityAutoConfiguration.class)
@ConditionalOnClass({EnableWebSecurity.class, ClientRegistration.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET) //서블릿 기반 웹 어플리케이션에서만
@Import({OAuth2ClientRegistrationRepositoryConfiguration.class})
public class OAuth2ClientAutoConfiguration {
    //왜 이런 빈 클래스를 만들어서 관리할까?
    //자동설정의 진입접으로 설정순서, 조건기반구성 나중에 다른 설정이 늘어난다면 추가하기 용이함
}
