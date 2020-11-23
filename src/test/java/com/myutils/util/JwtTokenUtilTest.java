package com.myutils.util;


import com.myutils.model.UserDetails;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

class JwtTokenUtilTest {

  private String secret;
  private JwtTokenUtil jwtTokenUtil;

  @Before
  public void setup() {
    this.secret = "some secret value";
    this.jwtTokenUtil = new JwtTokenUtil(secret);
  }

  @Test
  public void generate_and_validate_Token() {
    UserDetails userDetails = new UserDetails();
    userDetails.setUserName("ranjith");

    String token = jwtTokenUtil.generateToken(userDetails);
    Assert.assertTrue(jwtTokenUtil.validateToken(token, userDetails));
  }


}