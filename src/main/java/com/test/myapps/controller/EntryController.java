package com.test.myapps.controller;

import com.test.myapps.model.UserDetails;
import com.test.myapps.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EntryController {

  @Autowired
  private JwtTokenUtil jwtTokenUtil;

  @PostMapping("/login")
  public String login(@RequestBody UserDetails userDetails) {
    System.out.println(userDetails.getUserName());
    return jwtTokenUtil.generateToken(userDetails);
  }

  @PostMapping("/validate")
  public Boolean hello(@RequestBody UserDetails userDetails, @RequestHeader(value = "token") String bearerToken) {
    return jwtTokenUtil.validateToken(bearerToken, userDetails);
  }

}
