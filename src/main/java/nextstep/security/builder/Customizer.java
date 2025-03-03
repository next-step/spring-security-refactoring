package nextstep.security.builder;

@FunctionalInterface
public interface Customizer<T> {

    static <T> Customizer<T> withDefaults() {
        return (t) -> {
        };
    }

    void customize(T t);
}
