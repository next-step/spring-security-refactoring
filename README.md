# spring-security


1단계 - SecurityFilterChain 리팩터링

기존에 SecurityFilterChain과 필터 리스트를 명시적으로 구성하던 방식을 HttpSecurity와 스프링 시큐리티의 다양한 설정자(Configurer)를 활용하여 리팩터링한다. 
각 단계별로 필터를 리팩터링하고, 
스프링 부트의 Auto Configuration을 통해 기본 보안 설정을 활성화할 수 있도록 리팩터링하는 것을 목표로 한다.

- [X] HttpSecurity 객체 생성
- [X] HttpSecurity 에 csrf 필터 연결


2단계 - 인증 관련 리팩토링
기존에 직접 추가하던 UsernamePasswordAuthenticationFilter와 BasicAuthenticationFilter를 HttpSecurity의 .formLogin()과 .httpBasic() 메서드를 사용해 설정하는 방식으로 리팩터링한다.
- [X] formLogin 추가 
- [X] httpBasic 추가 

3단계 - 인가 관련 리팩터링
기존에 직접 추가하던 AuthorizationFilter를 HttpSecurity의 .authorizeHttpRequests() 설정을 통해 대체하고, 접근 권한 설정을 커스터마이징한다.

- [X] authorizeHttpRequests 추가 

4단계 - Auto Configuration 적용
