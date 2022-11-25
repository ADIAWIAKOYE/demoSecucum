package com.example.demosecucume.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {
    public Map<String,String> authenticate(
            String grantype, String username, String password, boolean withRefreshToken, String refreshToken){
        return null;
    }
}
