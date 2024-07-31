package com.EcomVerse.user_service.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String roles; // e.g., "ROLE_USER,ROLE_ADMIN"

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (roles == null || roles.isEmpty()) {
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return List.of(roles.split(",")).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }


    @Override
    public boolean isAccountNonExpired() {
        return true; // or add your own logic
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // or add your own logic
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // or add your own logic
    }

    @Override
    public boolean isEnabled() {
        return true; // or add your own logic
    }
}
