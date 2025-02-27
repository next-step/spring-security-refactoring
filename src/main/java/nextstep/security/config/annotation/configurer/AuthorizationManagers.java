package nextstep.security.config.annotation.configurer;

import nextstep.security.authorization.AuthorizationDecision;
import nextstep.security.authorization.AuthorizationManager;

public class AuthorizationManagers {
    public static <T> AuthorizationManager<T> not(AuthorizationManager<T> manager) {
        return (authentication, object) -> {
            AuthorizationDecision decision = manager.check(authentication, object);
            if (decision == null) {
                return null;
            }
            return new NotAuthorizationDecision(decision);
        };
    }

    private static final class NotAuthorizationDecision extends AuthorizationDecision {

        private NotAuthorizationDecision(AuthorizationDecision decision) {
            super(!decision.isGranted());
        }
    }
}
