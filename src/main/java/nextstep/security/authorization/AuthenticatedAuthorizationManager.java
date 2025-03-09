package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;

public class AuthenticatedAuthorizationManager<T> implements AuthorizationManager<T> {
    @Override
    public AuthorizationDecision check(Authentication authentication, T object) {
        boolean granted = (authentication != null && authentication.isAuthenticated());
        return new AuthorizationDecision(granted);
    }
}
