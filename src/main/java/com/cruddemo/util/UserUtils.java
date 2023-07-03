package com.cruddemo.util;

import com.cruddemo.security.CustomOAuth2User;
import com.cruddemo.security.CustomUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class UserUtils {

    public static CustomOAuth2User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomOAuth2User) {
//            OAuth2User oAuth2User = (OAuth2User) principal;
            return (CustomOAuth2User) principal;
        }
        return null;
    }

    public static String getCurrentUsername() {
        CustomOAuth2User customOAuth2User = getCurrentUser();
        if(customOAuth2User == null) {
           return null;
        }
        return customOAuth2User.getName();
    }

//    public static Long getCurrentUserId() {
//        CustomOAuth2User customOAuth2User = getCurrentUser();
//        if(customOAuth2User == null)
//            return null;
//        return customOAuth2User.getUserId();
//    }

}
