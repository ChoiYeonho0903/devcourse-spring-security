package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.user.UserService;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadPoolExecutor;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    //    @Autowired
//    public void setDataSource(DataSource dataSource) {
//        this.dataSource = dataSource;
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.jdbcAuthentication()
//            .dataSource(dataSource)
//            .usersByUsernameQuery(
//                "SELECT " +
//                    "login_id, passwd, true " +
//                    "FROM " +
//                    "USERS " +
//                    "WHERE " +
//                    "login_id = ?"
//            )
//            .groupAuthoritiesByUsername(
//                "SELECT " +
//                    "u.login_id, g.name, p.name " +
//                    "FROM " +
//                    "users u JOIN groups g ON u.group_id = g.id " +
//                    "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                    "JOIN permissions p ON p.id = gp.permission_id " +
//                    "WHERE " +
//                    "u.login_id = ?"
//            )
//            .getUserDetailsService().setEnableAuthorities(false)
//        ;
//    }

    public WebSecurityConfigure() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(@Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/asserts/**", "/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/api/user/").hasAnyRole("USER", "ADMIN")
            .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated()")
            .anyRequest().permitAll()
//            .accessDecisionManager(accessDecisionManager())
//            .expressionHandler(securityExpressionHandler())
            .and()
            .formLogin()
            .defaultSuccessUrl("/")
            .permitAll();
        /**
         * 로그아웃 설정
         */
        http.logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/")
            .invalidateHttpSession(true)
            .clearAuthentication(true);
        /**
         * remember me 설정
         */
        http.rememberMe()
            .rememberMeParameter("remember-me")
            .tokenValiditySeconds(300);
//        /**
//         * HTTP 요청을 HTTPS 요청으로 리다이렉트
//         */
//        http.requiresChannel()
//            .antMatchers("/api/**").requiresSecure();
        http.anonymous()
            .principal("thisIsAnonymousUser")
            .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN");
        /**
         * AccessDeniedException 예외에 대한 핸들러 설정
         */
        http.exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler());
        /**
         * 세션 전략 설정
         */
        http
            .sessionManagement()
            .sessionFixation().changeSessionId()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .invalidSessionUrl("/") //유효하지 않는 세션 감지시 이동 url
            .maximumSessions(1)
            .maxSessionsPreventsLogin(false);
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//            .withUser("user").password("{noop}user123").roles("USER")
//            .and()
//            .withUser("admin01").password("{noop}admin123").roles("ADMIN")
//            .and()
//            .withUser("admin02").password("{noop}admin123").roles("ADMIN")
//        ;
//    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
//        jdbcDao.setDataSource(dataSource);
//        jdbcDao.setEnableAuthorities(true);
//        jdbcDao.setEnableGroups(true);
//        jdbcDao.setUsersByUsernameQuery(
//            "SELECT " +
//                "login_id, passwd, true " +
//                "FROM " +
//                "USERS " +
//                "WHERE " +
//                "login_id = ?");
//        jdbcDao.setGroupAuthoritiesByUsernameQuery(
//            "SELECT " +
//                "u.login_id, g.name, p.name " +
//                "FROM " +
//                "users u JOIN groups g ON u.group_id = g.id " +
//                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                "JOIN permissions p ON p.id = gp.permission_id " +
//                "WHERE " +
//                "u.login_id = ?"
//        );
//        return jdbcDao;
//    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };

    }

    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        return new CustomWebSecurityExpressionHandler(
            new AuthenticationTrustResolverImpl(),
            "ROLE_"
        );
    }

//    @Bean
//    public AccessDecisionManager accessDecisionManager() {
//        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
//        voters.add(new WebExpressionVoter());
//        voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
//        return new UnanimousBased(voters);
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
