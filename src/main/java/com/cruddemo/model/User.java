package com.cruddemo.model;

import com.cruddemo.security.oauth.common.SecurityEnums;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String username;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    // TODO @Email Validation
    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "email_verified")
    private boolean emailVerified;

    @JsonProperty(value = "password", access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "password")
    private String password;

    @Column(name = "image_url")
    private String imageUrl;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(
            name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id")
    )
    @Column(name = "role")
    protected Set<String> roles = new HashSet<>();

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "registered_provider_name")
    @Enumerated(EnumType.STRING)
    private SecurityEnums.AuthProviderId registeredProviderName;

    @Column(name = "registered_provider_id")
    private String registeredProviderId;

    // Will be using same verificationCode and verificationCodeExpiresAt for both (email-verification and password reset)
    @Column(name = "verification_code")
    private String verificationCode;

    @Column(name = "verification_code_expires_at")
    private Instant verificationCodeExpiresAt;

}
