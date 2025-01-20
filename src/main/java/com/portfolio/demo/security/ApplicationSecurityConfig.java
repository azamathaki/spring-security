package com.portfolio.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.portfolio.demo.auth.ApplicationUserService;

import static com.portfolio.demo.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                    ApplicationUserService applicationUserService){
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                                .requestMatchers("/", "index", "/css/*", "/js/*").permitAll()
                                .requestMatchers("/api/**").hasRole(STUDENT.name())
                                // .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermisson())
                                // .requestMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermisson())
                                // .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermisson())
                                // .requestMatchers(HttpMethod.GET ,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                                .anyRequest().authenticated() // Require authentication for all requests
                )
                // .httpBasic(Customizer.withDefaults()); // Enable HTTP Basic Authentication
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/courses",true)
                        .passwordParameter("password") // if you not use default parameter
                        .usernameParameter("username") // use this 2line for username and password
                        .permitAll()
                )
                .rememberMe(rememberMe -> rememberMe
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me") // if paramater changes change this line too
                )
                .logout(logout -> logout
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessUrl("/login")
                    .permitAll()
                );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;

    }


            // IN MEMORY USE CASE OF USERS IN SPRING SECURITY
    // @Bean
    // public UserDetailsService userDetailsService(){
    //     UserDetails annaSmithUser = User.builder()
    //             .username("annasmith")
    //             .password(passwordEncoder.encode("password"))
    //             // .roles(STUDENT.name()) //ROLE_STUDENT
    //             .authorities(STUDENT.getGrantedAuthorities())
    //             .build();

    //     UserDetails lindaUser =  User.builder()
    //             .username("linda")
    //             .password(passwordEncoder.encode("password123"))
    //             // .roles(ADMIN.name()) //ROLE_ADMIN
    //             .authorities(ADMIN.getGrantedAuthorities())
    //             .build();

    //     UserDetails tomUser =  User.builder()
    //             .username("tom")
    //             .password(passwordEncoder.encode("password123"))
    //             // .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
    //             .authorities(ADMINTRAINEE.getGrantedAuthorities())
    //             .build();

    //     return new InMemoryUserDetailsManager(
    //         annaSmithUser,
    //         lindaUser,
    //         tomUser
    //     );
    // }
}
