package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.authentication.AuthenticationException;

public class AuthenticatedAuthorizationManager<T> implements AuthorizationManager<T> {
    @Override
    public AuthorizationDecision check(Authentication authentication, T object) {
        if (authentication == null) {
            throw new AuthenticationException("인증이 필요합니다.");
        }
        boolean granted = authentication.isAuthenticated();
        return new AuthorizationDecision(granted);
    }
}
