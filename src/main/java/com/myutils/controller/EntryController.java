package com.myutils.controller;

import com.myutils.model.UserDetails;
import com.myutils.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EntryController {

  private JwtTokenUtil jwtTokenUtil;

  /**
   * Constructor based injection
   *
   * @param jwtTokenUtil dependency injection.
   */
  @Autowired
  public EntryController(JwtTokenUtil jwtTokenUtil) {
    this.jwtTokenUtil = jwtTokenUtil;
  }

  @PostMapping("/login")
  public String login(@RequestBody UserDetails userDetails) {
    return jwtTokenUtil.generateToken(userDetails);
  }

  @PostMapping("/validate")
  public Boolean validateToken(@RequestBody UserDetails userDetails,
      @RequestHeader(value = "token") String bearerToken) {
    return jwtTokenUtil.validateToken(bearerToken, userDetails);
  }

}
