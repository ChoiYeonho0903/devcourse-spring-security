# spring-security

## 미션 1
### 1. configure(AuthenticationManagerBuilder auth) 메소드 orverride
- passwordEncoder는 NoOpPasswordEncoder로 사용 (DelegatingPasswordEncoder)
- 기본 로그인 계정을 AuthenticationManagerBuilder 클래스를 통해 추가
   - user, user123, USER
   - admin, admin123, ADMIN
### 2. 로그아웃, Cookie 기반 자동 로그인 (Remember-Me) 기능 설정
- HttpSecurity 클래스의 logout() API를 통해 로그아웃 기능을 설정
   - 로그아웃 처리 path "/logout"
   - 로그아웃 성공 후 리다이렉션 path "/"
- HttpSecurity 클래스의 rememberMe() API를 통해 Cookie 기반 자동 로그인 기능을 설정
   - 파라미터명 "remember-me"
   - 자동 로그인 토큰 유효기간 5분
