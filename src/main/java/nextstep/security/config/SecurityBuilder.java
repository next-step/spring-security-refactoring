package nextstep.security.config;

import java.util.HashMap;
import java.util.Map;

public abstract class SecurityBuilder<T> {
    protected final Map<Class<?>, Object> sharedObjects = new HashMap<>();

    public <S> void setSharedObject(Class<S> key, S value) {
        sharedObjects.put(key, value);
    }

    public <S> S getSharedObject(Class<S> key) {
        return key.cast(sharedObjects.get(key));
    }

    public abstract T build();
}
