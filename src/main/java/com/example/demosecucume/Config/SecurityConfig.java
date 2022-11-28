package com.example.demosecucume.Config;

import com.example.demosecucume.Entities.AppUser;
import com.example.demosecucume.service.AccountService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
//@NoArgsConstructor
public class SecurityConfig{ //extends WebSecurityConfigurerAdapter {

    private RsakeysConfig rsakeysConfig;
    private PasswordEncoder passwordEncoder;
   private AccountService accountService;
    private UserDetailsService userDetailsService;
  /// private CustomUserDetailsService

    public SecurityConfig(RsakeysConfig rsakeysConfig, PasswordEncoder passwordEncoder, AccountService accountService, UserDetailsService userDetailsService){
        this.rsakeysConfig = rsakeysConfig;
        this.passwordEncoder = passwordEncoder;
        this.accountService = accountService;


        this.userDetailsService = userDetailsService;
    }
///////////////////////////////////////////////////



 /*   @Bean
    public BCryptPasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

   // @Bean
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // super.configure(auth);
        //  userdetailserv logique pour charger les détails de l'utilisateur par nom ou par e-mail à partir de la base de données
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    //auth et autorisation
    @Override
    protected void configure(HttpSecurity http) throws Exception {


        //CustonAuthentificationFilter custonAuthentificationFilter=new CustonAuthentificationFilter(authenticationManagerBean());


        http.csrf().disable();
        //desactiver parceque github ne se redirigepas vers bienvenu
        //http.sessionManagement().sessionCreationPolicy(STATELESS);
        http.authorizeRequests().antMatchers("/token/**").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/dataTest/").hasAnyAuthority("USER","ADMIN");
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/user/").hasAnyAuthority("USER","ADMIN");
        http.authorizeRequests().antMatchers(HttpMethod.POST,"/saveusers/").hasAnyAuthority("ADMIN");
        //http.authorizeRequests().antMatchers("/", "/error", "/webjars/**").permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.oauth2Login();


       // http.addFilter(custonAuthentificationFilter);
       // http.addFilterBefore(new customAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }*/



/////////////////////////////////////////////////////////////////////
    //pour une authentification personnaliser
   // @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationManager authenticationManager(){//UserDetailsService userDetailsService){
      var authProvider =  new DaoAuthenticationProvider();
          authProvider.setPasswordEncoder(passwordEncoder);
     authProvider.setUserDetailsService(userDetailsService);
        // authProvider.setPasswordEncoder(passwordEncoder);
      return new ProviderManager(authProvider);
    }



// @Bean

  /*  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser=accountService.trouverUserParSonNom(username);
                Collection<GrantedAuthority> authorities=new ArrayList<>();
                appUser.getAppRoles().forEach(appRole -> {
                    authorities.add(new SimpleGrantedAuthority(appRole.getNomrole()));
                });
                return new User(appUser.getNom(),appUser.getPassword(),authorities);

            }
        });

    }*/



   /* @Bean
    public PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }*/

   /* @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();

        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        return authenticationProvider;
    }*/


   /*@Bean
    public UserDetailsService inMemoryUserDetailsManager(){
        return new InMemoryUserDetailsManager(
                User.withUsername("user1").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                User.withUsername("user2").password(passwordEncoder.encode("1234")).authorities("USER").build(),
                User.withUsername("user3").password(passwordEncoder.encode("1234")).authorities("USER","ADMIN").build(),
                User.withUsername("admin").password(passwordEncoder.encode("1234")).authorities("ADMIN").build()

        );
    }*/

   // @Bean
    public  UserDetailsService userDetailsService(AuthenticationManagerBuilder auth) throws Exception {
         auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser=accountService.trouverUserParSonNom(username);
                Collection<GrantedAuthority> authorities=new ArrayList<>();
                appUser.getAppRoles().forEach(appRole -> {
                    authorities.add(new SimpleGrantedAuthority(appRole.getNomrole()));
                });
                return new User(appUser.getNom(),appUser.getPassword(),authorities);
            }
        });

        return null;
    }

  /*  @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf->csrf.disable())
                .authorizeRequests(auth->auth.antMatchers("/token/**").permitAll())
                .authorizeRequests(auth->auth.antMatchers(HttpMethod.GET,"/colaborateur/afficheruser/").hasAnyAuthority("USER","ADMIN"))
                .authorizeRequests(auth->auth.antMatchers(HttpMethod.POST,"/colaborateur/saveusers/").hasAnyAuthority("ADMIN"))
                .authorizeRequests(auth->auth.antMatchers(HttpMethod.POST,"/colaborateur/saverole/").hasAnyAuthority("ADMIN"))
                // Toutes les requetes nessecite une authentification
//                .authenticationProvider(authenticationProvider())
                .authorizeRequests(auth->auth.anyRequest().authenticated())

                .sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .httpBasic(Customizer.withDefaults())

                .build();
    }*/


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity)throws  Exception{

        return httpSecurity
                .csrf(csrf->csrf.disable())
                //Il donner l'autorisation au user à s'authentifier à travers ce url
                .authorizeRequests(auth->auth.antMatchers("/token/**").permitAll())
                .authorizeRequests(auth-> {
                            try {
                                auth.anyRequest().authenticated()
                                        .and()
                                        .oauth2Login();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                )


                //.sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .formLogin().and()
                .httpBasic(Customizer.withDefaults())
                .build();
    }





    ////////////////////////////////////////////////////////////

   /* @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/dataTest").hasRole("ADMIN")
                .antMatchers("/dataTest").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .oauth2Login();
    }*/
    ////////////////////////////////////////////



    @Bean
     JwtEncoder jwtEncoder(){
      JWK jwk= new RSAKey.Builder(rsakeysConfig.publicKey()).privateKey(rsakeysConfig.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
     JwtDecoder jwtDecoder(){

        return NimbusJwtDecoder.withPublicKey(rsakeysConfig.publicKey()).build();
    }



}
