package nextstep.security.builder;

public interface SecurityConfigurer<O, B> {

    void init(B builder);


    void configure(B builder);
}
