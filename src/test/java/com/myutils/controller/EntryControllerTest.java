package com.myutils.controller;


import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.myutils.model.UserDetails;
import com.myutils.util.JwtTokenUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

class EntryControllerTest {

  private JwtTokenUtil jwtTokenUtil;
  private EntryController entryController;
  private static final String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyYW5q"
      + "aXRoIiwiZXhwIjoxNjA1MTk2NzQ0LCJpYXQiOjE2MDUxOTY2MjR9.IlLEecfP7-xL78"
      + "bnpdnilOuBpPkMa_OI9hINLCBuVCk";

  @Before
  public void setup() {
    this.jwtTokenUtil = mock(JwtTokenUtil.class);
    this.entryController = new EntryController(jwtTokenUtil);
  }

  @Test
  public void validate_login_AuthTokenResponse() {
    UserDetails userDetails = new UserDetails();
    userDetails.setPassword("sdsdd");
    userDetails.setUserName("ranjith");

    when(jwtTokenUtil.generateToken(userDetails)).thenReturn(token);

    Assert.assertEquals(token, entryController.login(userDetails));
  }

  @Test
  public void validate_API_token_response() {
    UserDetails userDetails = new UserDetails();
    userDetails.setPassword("sdsdd");
    userDetails.setUserName("ranjith");

    when(jwtTokenUtil.validateToken(token, userDetails)).thenReturn(true);
    Assert.assertTrue(entryController.validateToken(userDetails, token));
  }

}