package com.cruddemo.service;

import com.cruddemo.model.User;
import com.cruddemo.repository.UserRepository;
import com.cruddemo.security.AppSecurityUtils;
import com.cruddemo.security.CustomUserDetails;
import com.cruddemo.util.FileUpload;
import com.cruddemo.utils.exceptions.AppExceptionConstants;
import com.cruddemo.utils.exceptions.ResourceNotFoundException;
import jakarta.transaction.Transactional;
import org.hibernate.Hibernate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class UserServiceImpl implements UserService {


    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void save(MultipartFile file, User user) throws IOException {
        userRepository.save(user);
        FileUpload.upload(file,user.getUsername());
    }

    @Override
    public void update(User user) {
        userRepository.save(user);
    }

    @Override
    public User login(String username, String password) {
        return userRepository.findByUsernameAndPassword(username, password);
    }

    @Override
    public List<User> getAllUser() {
        List<User> users = userRepository.findAll();
        return users;
    }

    @Override
    public Optional<User> findOptionalUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
//    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public User createUser(User requestUserDTO) {
        if (ObjectUtils.isEmpty(requestUserDTO.getRoles())) {
            requestUserDTO.setRoles(Set.of(AppSecurityUtils.ROLE_DEFAULT));
        }
        boolean isFromCustomBasicAuth = requestUserDTO.getRegisteredProviderName().equals(requestUserDTO.getRegisteredProviderName());
        if (isFromCustomBasicAuth && requestUserDTO.getPassword() != null) {
            requestUserDTO.setPassword(passwordEncoder.encode(requestUserDTO.getPassword()));
        }
        User userEntity = requestUserDTO;
        boolean existsByEmail = userRepository.existsByEmail(userEntity.getEmail());
        if (existsByEmail) {
            throw new ResourceNotFoundException(AppExceptionConstants.USER_EMAIL_NOT_AVAILABLE);
        }
        userRepository.save(userEntity);
//        sendVerificationEmail(userEntity.getEmail());
        return userEntity;
    }

    @Override
    public User updateUser(User reqUserDTO) {
        User userEntity = userRepository.findById(reqUserDTO.getId())
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        userEntity.setFullName(reqUserDTO.getFullName());
        userEntity.setImageUrl(reqUserDTO.getImageUrl());
        userEntity.setPhoneNumber(reqUserDTO.getPhoneNumber());
        userRepository.save(userEntity);
        return userEntity;
    }
}
