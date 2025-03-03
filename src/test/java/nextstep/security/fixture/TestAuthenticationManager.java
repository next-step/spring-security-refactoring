package nextstep.security.fixture;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationManager;

public class TestAuthenticationManager implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) {
        return authentication;
    }
}


