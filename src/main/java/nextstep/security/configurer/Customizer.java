package nextstep.security.configurer;

@FunctionalInterface
public interface Customizer<T> {

    void customize(T t);

    static <T> Customizer<T> withDefaults() {
        return t -> {
        };
    }

}
