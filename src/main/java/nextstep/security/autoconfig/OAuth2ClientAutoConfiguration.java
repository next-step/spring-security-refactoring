package nextstep.security.autoconfig;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration(before = SecurityAutoConfiguration.class)
@Import({OAuth2ClientRegistrationRepositoryConfiguration.class})
public class OAuth2ClientAutoConfiguration {

}
