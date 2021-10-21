package com.example.springsecurityoauth2.util;

import com.example.springsecurityoauth2.config.AppProperties;
import com.example.springsecurityoauth2.exception.OAuth2AuthenticationProcessingException;
import com.example.springsecurityoauth2.security.UserPrincipal;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@AllArgsConstructor
@Service
public class TokenProvider {

    private AppProperties appProperties;

    public String creatToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationTime());

        return Jwts.builder()
            .setSubject(Long.toString(userPrincipal.getId()))
            .setIssuedAt(new Date())
            .setExpiration(expiryDate)
            .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
            .compact();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(appProperties.getAuth().getTokenSecret())
            .parseClaimsJws(token)
            .getBody();
        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) { // 유효하지 않은 JWT 서명
            throw new OAuth2AuthenticationProcessingException("not valid jwt signature");
        } catch (MalformedJwtException e) { // 유효하지 않은 JWT
            throw new OAuth2AuthenticationProcessingException("not valid jwt");
        } catch (io.jsonwebtoken.ExpiredJwtException e) { // 만료된 JWT
            throw new OAuth2AuthenticationProcessingException("expired jwt");
        } catch (io.jsonwebtoken.UnsupportedJwtException e) { // 지원하지 않는 JWT
            throw new OAuth2AuthenticationProcessingException("unsupported jwt");
        } catch (IllegalArgumentException e) { // 빈값
            throw new OAuth2AuthenticationProcessingException("empty jwt");
        }
    }

}