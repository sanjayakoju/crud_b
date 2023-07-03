package com.cruddemo.controller;

import com.cruddemo.model.User;
import com.cruddemo.service.UserService;
import com.cruddemo.util.UserUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.management.relation.Role;
import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;

    public UserController(@Autowired UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<?> save(@RequestParam("file") MultipartFile file,
                                  @RequestParam("user") String user) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        userService.save(file,mapper.readValue(user, User.class));
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

//    @PutMapping
//    public ResponseEntity<?> update(@RequestBody User user) {
//        userService.save(user);
//        return new ResponseEntity<>(HttpStatus.OK);
//    }

    @GetMapping
    public ResponseEntity<?> getAllUser() {
        String username = UserUtils.getCurrentUsername();
        System.out.println("Login Username : "+ username);
        List<User> users = userService.getAllUser();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }
}
