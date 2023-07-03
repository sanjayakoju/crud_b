package com.cruddemo.security;

import com.cruddemo.model.User;
import com.cruddemo.repository.UserRepository;
import com.cruddemo.utils.exceptions.AppExceptionConstants;
import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(AppExceptionConstants.BAD_LOGIN_CREDENTIALS));
        return CustomUserDetails.buildFromUserEntity(userEntity);
    }
}
