package com.AuthService.Controller;

import com.AuthService.Entity.Role;
import com.AuthService.Entity.User;
import com.AuthService.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private RestTemplate template;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Check if the request is secured
            if (validator.isSecured.test(exchange.getRequest())) {
                // Check for the Authorization header
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("Missing authorization header");
                }

                // Extract the token from the Authorization header
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                String token;

                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7);
                } else {
                    throw new RuntimeException("Invalid authorization header format");
                }

                // Validate the token and extract username
                String username;
                try {
                    jwtUtil.validateToken(token);
                    username = jwtUtil.getUsernameFromJWT(token); // Use your method to extract the username
                } catch (Exception e) {
                    System.out.println("Invalid access...!");
                    throw new RuntimeException("Unauthorized access to the application: " + e.getMessage());
                }

                // Call the user service to validate the user
                try {
                    ResponseEntity<User> userResponse = template.getForEntity("http://USER-SERVICE/api/users/username/" + username, User.class);
                    if (userResponse.getStatusCode().is2xxSuccessful()) {
                        User user = userResponse.getBody();
                        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                                user.getUser_name(), user.getPassword(), mapRolesToAuthorities(user.getRole()) // Assuming User has a method getRoles()
                        );

                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails((HttpServletRequest) exchange.getRequest()));
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken); // Set authentication in Security Context
                    } else {

                        throw new RuntimeException("User not found: " + username);
                    }
                } catch (Exception e) {
                    System.out.println("User not found...!");
                    throw new RuntimeException("Unauthorized access to the application: " + e.getMessage());
                }
            }

            // Proceed with the request
            return chain.filter(exchange);
        };
    }

    public static class Config {
    }
    private Collection<? extends GrantedAuthority>mapRolesToAuthorities (Set<Role> roles){
        return roles.stream().map(role->new SimpleGrantedAuthority(role.getRoletype())).collect(Collectors.toList());
    }
}
