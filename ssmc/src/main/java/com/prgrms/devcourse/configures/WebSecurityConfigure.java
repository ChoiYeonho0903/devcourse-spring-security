package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.jwt.JwtAuthenticationFilter;
import com.prgrms.devcourse.jwt.JwtAuthenticationProvider;
import com.prgrms.devcourse.user.UserService;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final JwtConfigure jwtConfigure;

    public WebSecurityConfigure(JwtConfigure jwtConfigure) {
        this.jwtConfigure = jwtConfigure;
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        Jwt jwt = getApplicationContext().getBean(Jwt.class);
        return new JwtAuthenticationFilter(jwtConfigure.getHeader(), jwt);
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
            jwtConfigure.getIssuer(),
            jwtConfigure.getClientSecret(),
            jwtConfigure.getExpirySeconds()
        );
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(Jwt jwt, UserService userService) {
        return new JwtAuthenticationProvider(jwt, userService);
    }

    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder builder, JwtAuthenticationProvider provider) {
        builder.authenticationProvider(provider);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
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
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
        @Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate) {
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
            .antMatchers("/api/user/me").hasAnyRole("USER", "ADMIN")
            .anyRequest().permitAll()
            .and()
            .csrf()
                .disable()
            .headers()
                .disable()
            .formLogin()
                .disable()
            .httpBasic()
                .disable()
            .logout()
                .disable()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
        /**
         * 예외처리 핸들러
         */
            .exceptionHandling()
            .accessDeniedHandler(accessDeniedHandler())
            .and()
            .addFilterAfter(jwtAuthenticationFilter(), SecurityContextPersistenceFilter.class);
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
