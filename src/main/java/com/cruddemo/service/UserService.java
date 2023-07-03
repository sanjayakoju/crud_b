package com.cruddemo.service;

import com.cruddemo.model.User;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public interface UserService {

    void save(MultipartFile file, User user) throws IOException;
    void update(User user);
    User login(String username, String password);

    List<User> getAllUser();

    Optional<User> findOptionalUserByEmail(String email);

    User createUser(User userDTO);

    User updateUser(User userDTO);
}
