package com.ibetar.springsecuritypractice.security;

import com.ibetar.springsecuritypractice.auth.ApplicationUserService;
import com.ibetar.springsecuritypractice.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.ibetar.springsecuritypractice.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter  {

    //WebSecurityConfigurerAdapter
//    @Override
//    public ApplicationSecurityConfig(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic();
//    }
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    //JWT -> method for creating first filter (username and password) with JwtUsernameAndPasswordAuthenticationFilter.
    // This is stateless
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
                .authorizeRequests()
                .antMatchers("/","index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                ;
    }
//#method used in form base authentication
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
////                .and()
//                .authorizeRequests()
//                .antMatchers("/","index", "/css/*", "/js/*").permitAll()
//                .antMatchers("/api/**").hasRole(STUDENT.name())
////                .antMatchers(HttpMethod.DELETE,"/manage/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.POST,"/manage/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.PUT,"/manage/api/**").hasAuthority(COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.GET,"/manage/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses",true)
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                    .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                        .key("Something very secured")
//                    .rememberMeParameter("remember-me")
//                .and()
//                .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))//delete this line if csrf is enabled
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID","remember-me")
//                    .logoutSuccessUrl("/login");
//    }
////this class was used only for create a temporal database using memory -> "InMemoryUserDetailsManager"
//    @Override
//    @Bean
//    public UserDetailsService userDetailsServiceBean() {
//       UserDetails annaSmithUser = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
////                .roles(ApplicationUserRole.STUDENT.name())
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ApplicationUserRole.ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails aruUser = User.builder()
//                .username("aru")
//                .password(passwordEncoder.encode("password321"))
////                .roles(ApplicationUserRole.ADMINTRAINEE.name())
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//       return new InMemoryUserDetailsManager(
//               annaSmithUser,
//               aruUser,
//               lindaUser
//       );
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
