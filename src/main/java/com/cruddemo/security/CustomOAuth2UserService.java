package com.cruddemo.security;

import com.cruddemo.model.User;
import com.cruddemo.security.oauth.common.CustomAbstractOAuth2UserInfo;
import com.cruddemo.security.oauth.common.OAuth2Util;
import com.cruddemo.security.oauth.common.SecurityEnums;
import com.cruddemo.service.UserService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {


    @Autowired
    private UserService userService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest,
                                         OAuth2User oAuth2User) {
        // Mapped OAuth2User to specific CustomAbstractOAuth2UserInfo for that registration id
        // clientRegistrationId - (google, facebook, gitHub, or Custom Auth Provider - ( keyClock, okta, authServer etc.)
        String clientRegistrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        CustomAbstractOAuth2UserInfo customAbstractOAuth2UserInfo = OAuth2Util.getOAuth2UserInfo(clientRegistrationId, oAuth2User.getAttributes());

        // Check if the email is provided by the OAuthProvider
        SecurityEnums.AuthProviderId registeredProviderId = SecurityEnums.AuthProviderId.valueOf(clientRegistrationId);
        String userEmail = customAbstractOAuth2UserInfo.getEmail();
        if (!StringUtils.hasText(userEmail)) {
            throw new InternalAuthenticationServiceException("Sorry, Couldn't retrieve your email from Provider " + clientRegistrationId + ". Email not available or Private by default");
        }

        // Determine is this [ Login ] or [ New Sign up ]
        // Sign In (email will be present in our database)  OR Sign Up ( if don't have user email, we need to register user, and save email into db)
        Optional<User> optionalUserByEmail = userService.findOptionalUserByEmail(userEmail);
        if (optionalUserByEmail.isEmpty()) {
            optionalUserByEmail = Optional.of(registerNewOAuthUser(oAuth2UserRequest, customAbstractOAuth2UserInfo));
        }
        User userDTO = optionalUserByEmail.get();
        if (userDTO.getRegisteredProviderName().equals(registeredProviderId)) {
//            updateExistingOAuthUser(userDTO, customAbstractOAuth2UserInfo);
        } else {
            String incorrectProviderChoice = "Sorry, this email is linked with \"" + userDTO.getRegisteredProviderName() + "\" account. " +
                    "Please use your \"" + userDTO.getRegisteredProviderName() + "\" account to login.";
            throw new InternalAuthenticationServiceException(incorrectProviderChoice);
        }


        List<GrantedAuthority> grantedAuthorities = oAuth2User.getAuthorities().stream().collect(Collectors.toList());
        grantedAuthorities.add(new SimpleGrantedAuthority(AppSecurityUtils.ROLE_DEFAULT));
        User userEntity = userDTO;
        return CustomUserDetails.buildWithAuthAttributesAndAuthorities(userEntity, grantedAuthorities, oAuth2User.getAttributes());
    }

    private User registerNewOAuthUser(OAuth2UserRequest oAuth2UserRequest,
                                         CustomAbstractOAuth2UserInfo customAbstractOAuth2UserInfo) {
        User userDTO = new User();
        userDTO.setUsername(customAbstractOAuth2UserInfo.getName());
        userDTO.setFullName(customAbstractOAuth2UserInfo.getName());
        userDTO.setEmail(customAbstractOAuth2UserInfo.getEmail());
        userDTO.setRegisteredProviderName(SecurityEnums.AuthProviderId.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        userDTO.setRegisteredProviderId(customAbstractOAuth2UserInfo.getId());
        userDTO.setRoles(Set.of(AppSecurityUtils.ROLE_DEFAULT));
        userDTO.setEmailVerified(true);
        User returnedUser = userService.createUser(userDTO);
        return returnedUser;
    }

    private void updateExistingOAuthUser(User existingUserDTO,
                                         CustomAbstractOAuth2UserInfo customAbstractOAuth2UserInfo) {
        existingUserDTO.setFullName(customAbstractOAuth2UserInfo.getName());
        existingUserDTO.setImageUrl(customAbstractOAuth2UserInfo.getImageUrl());
        User updatedUserDTO = userService.updateUser(existingUserDTO);
        BeanUtils.copyProperties(updatedUserDTO, existingUserDTO);
    }
}
