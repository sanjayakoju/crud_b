package com.cruddemo.security;


import com.cruddemo.model.User;
import com.cruddemo.utils.AppUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.function.Function;

@Slf4j
@Component
public class JWTTokenProvider {

    private static final String HEADER_AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    private static final String BEARER_TOKEN_START = "Bearer ";

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.token.expire-seconds}")
    private long tokenExpireInSeconds;

    @PostConstruct
    protected void init() {
        jwtSecret = Base64.getEncoder().encodeToString(jwtSecret.getBytes());
    }

    //generate token for user
    public String generateToken(Authentication authentication) throws JsonProcessingException {
        CustomUserDetails userDetail = (CustomUserDetails) authentication.getPrincipal();
        User user = userDetail.getUserEntity();
        Claims claims = Jwts.claims().setSubject(user.getUsername());

//        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        System.out.println("Username + " + user.getUsername());
        System.out.println("Authorities + " + user.getRoles());
        ObjectMapper objectMapper = new ObjectMapper();
        claims.put("roles", objectMapper.writeValueAsString(user.getRoles()));

        return doGenerateToken(claims);
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Claims claims) {
        try {
            long refreshTokenExpirationInMillis = 1 * 24 * 60 * 60 * 1000; // 1 day

            final String accessToken = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + (tokenExpireInSeconds)))
                    .signWith(SignatureAlgorithm.HS256, jwtSecret)
                    .compact();

            final String refreshToken = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + (refreshTokenExpirationInMillis)))
                    .signWith(SignatureAlgorithm.HS256, jwtSecret)
                    .compact();
            Map<String, String> map = new HashMap<>();
            map.put("accessToken", accessToken);
            map.put("expiredIn", String.valueOf(new Date(System.currentTimeMillis() + (tokenExpireInSeconds))));
            map.put("refreshToken", refreshToken);
            log.info("JWT Token Created Successfully !!!");
            return map.toString();
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid : JWT Token Builder !!!");
        }
        return null;
    }

    //validate token
    public boolean validateToken(String token, CustomUserDetails userDetails) {
        final String userName = getUsernameFromToken(token);
        try {
            if ((userName.equals(userDetails.getUsername())) && !isTokenExpired(token)) {
                return true;
            }
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid: JWT Token !!!");
            ex.printStackTrace();
        }
        return false;
    }

    private boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationFromToken(token);
            return expiration.before(new Date());
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        }
        return false;
    }

    //retrieve expiration date from jwt token
    private Date getExpirationFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        try {
            return getClaimFromToken(token, Claims::getSubject);
        } catch (UsernameNotFoundException ex) {
            log.error("User Not Found !!!");
        }
        return null;
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        try {
            final Claims claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        } catch (NullPointerException ex) {
            log.error("Claims Not Found !!!");
            ex.printStackTrace();
        }
        return null;
    }

    //for retrieving any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        Claims claims = null;
        try {
            claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException ex) {
            log.error("Expired : JWT Token !!!");
        } catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            log.error("Invalid: JWT Token");
            ex.printStackTrace();
        }
        return claims;
    }

    public Authentication getAuthenticationFromToken(String token) {
        Claims body = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        // Parsing Claims Data
        String email = (String) body.get("email");
        User user = AppUtils.fromJson(body.get("user").toString(), User.class);
//        UserEntity userEntity = userMapper.toEntity(userDTO);
        Set<String> authoritiesSet = AppUtils.fromJson(body.get("authorities").toString(), (Class<Set<String>>) ((Class) Set.class));
        Collection<? extends GrantedAuthority> grantedAuthorities = AppSecurityUtils.convertRolesSetToGrantedAuthorityList(authoritiesSet);
        Map<String, Object> attributes = AppUtils.fromJson(body.get("attributes").toString(), (Class<Map<String, Object>>) (Class) Map.class);

        // Setting Principle Object

        CustomUserDetails customUserDetails = CustomUserDetails.buildWithAuthAttributesAndAuthorities(user, grantedAuthorities, attributes);
        customUserDetails.setAttributes(attributes);
        return new UsernamePasswordAuthenticationToken(customUserDetails, "", customUserDetails.getAuthorities());
    }

    public String getBearerTokenFromRequestHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TOKEN_START)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public boolean validateJWTToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            if (claims.getBody().getExpiration().before(new Date())) {
                return false;
            }
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

    public String createJWTToken(Authentication authentication) {
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        Set<String> authoritiesSet = AppSecurityUtils.convertGrantedAuthorityListToRolesSet(customUserDetails.getAuthorities());

        String authoritiesJsonValue = AppUtils.toJson(authoritiesSet);
        String attributesJsonValue = AppUtils.toJson(customUserDetails.getAttributes());
        String userJsonValue = AppUtils.toJson(customUserDetails.getUserEntity());

        Claims claims = Jwts.claims().setSubject(customUserDetails.getEmail());
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("email", customUserDetails.getEmail());
        claimsMap.put("user", userJsonValue);
        claimsMap.put("authorities", authoritiesJsonValue);
        claimsMap.put("attributes", attributesJsonValue);
        claims.putAll(claimsMap);

        Date now = new Date();
        Date validity = new Date(now.getTime() + tokenExpireInSeconds);

        return Jwts.builder()
                .setSubject(customUserDetails.getEmail())
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
}