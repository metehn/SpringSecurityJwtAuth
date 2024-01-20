package com.metehan.SpringSecurityJwtAuth.config;

import com.metehan.SpringSecurityJwtAuth.token.Token;
import com.metehan.SpringSecurityJwtAuth.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.PrintWriter;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // HTTP 400 Bad Request yanıtı ve bir hata mesajı döndür
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        jwt = authHeader.substring(7);
        Token storedToken = tokenRepository.findByToken(jwt).orElse(null);

        if(storedToken != null){
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            tokenRepository.save(storedToken);
        }else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

    }
}
