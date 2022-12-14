package com.example.demosecucume.Web;

import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@NoArgsConstructor

public class AuthController {
    private JwtEncoder jwtEncoder;

    private JwtDecoder jwtDecoder;

    private AuthenticationManager authenticationManager;

    private UserDetailsService userDetailsService;



    public AuthController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> jwtToken(
            String grantype, String username, String password, boolean withRefreshToken, String refreshToken){

        String subjecte = null;
        String scope = null;



        if (grantype.equals("password")){
            Authentication   authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
             subjecte=authentication.getName();
             scope =  authentication.getAuthorities()
                     .stream().map(auth -> auth.getAuthority())
                     .collect(Collectors.joining(""));

        }else if (grantype.equals("refreshToken")){
            if (refreshToken==null){
                return new ResponseEntity<>(Map.of("errorMessage", "Refresh Token is required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage", e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
            subjecte= decodeJWT.getSubject();
            UserDetails userDetails = userDetailsService.loadUserByUsername(subjecte);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            scope=authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));

        }


        Map<String, String> idToken = new HashMap<>();
        Instant instant = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subjecte)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                .issuer("security-service")
                //pour renvoyer le role
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        if (withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                    .subject(subjecte)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(30, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefrechToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refreshToken", jwtRefrechToken);
        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);
    }
}
