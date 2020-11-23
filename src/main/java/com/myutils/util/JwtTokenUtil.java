package com.myutils.util;

import com.myutils.model.UserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;


@Component
public class JwtTokenUtil implements Serializable {

  private static final long serialVersionUID = 1234567L;

  private final String secret;

  @Autowired
  public JwtTokenUtil(@Value("${jwt.key.value}") String secret) {
    this.secret = Base64.getEncoder()
        .encodeToString(secret.getBytes());
  }

  /* Sample
  String jws = Jwts.builder()
  .setIssuer("Stormpath")
  .setSubject("msilverman")
  .claim("name", "Micah Silverman")
  .claim("scope", "admins")
  // Fri Jun 24 2016 15:33:42 GMT-0400 (EDT)
  .setIssuedAt(Date.from(Instant.ofEpochSecond(1466796822L)))
  // Sat Jun 24 2116 15:33:42 GMT-0400 (EDT)
  .setExpiration(Date.from(Instant.ofEpochSecond(4622470422L)))
  .signWith(
    SignatureAlgorithm.HS256,
    TextCodec.BASE64.decode("Yn2kjibddFAWtnPJ2AFlL8WXmohJMCvigQggaEypa5E=")
  )
  .compact();
   */

  /**
   * Method generate token with HS256 algorithm signed with secret key and with subject as
   * username.
   */
  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return Jwts.builder().setClaims(claims).setSubject(userDetails.getUserName()).setIssuedAt(
        new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(2)))
        .signWith(SignatureAlgorithm.HS256, secret).compact();
  }

  /**
   * Checks the value from Token and username both are same token for the exact user. Also verifies
   * the expiry also grater than current time
   */
  public Boolean validateToken(String token, UserDetails userDetails) {
    final String userNameFromToken = getClaimFromToken(token, Claims::getSubject);
    final Date getExpirationTimeFromToken = (Date) getClaimFromToken(token, Claims::getExpiration);
    return userDetails.getUserName().equals(userNameFromToken) && getExpirationTimeFromToken
        .after(new Date());
  }

  /**
   * Method to get values from token. Second argument is Function interface Function accepts the
   * first argument(Claims) and apply then produces the result in second argument.
   */
  private <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction) {
    Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    return claimsTFunction.apply(claims);
  }

}
