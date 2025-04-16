/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {
	private final LessonDataSource dataSource;
	
	private JWTHeaderJKUEndpoint(LessonDataSource dataSource) {
	    this.dataSource = dataSource;
	  }
  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
	  if (StringUtils.isEmpty(token)) {
	      return failed(this).feedback("jwt-invalid-token").build();
	    } else {
	      try {
	        final String[] errorMessage = {null};
	        Jwt jwt =
	            Jwts.parser()
	                .setSigningKeyResolver(
	                    new SigningKeyResolverAdapter() {
	                      @Override
	                      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
	                        final String kid = (String) header.get("kid");
	                        try (var connection = dataSource.getConnection()) {
	                          ResultSet rs =
	                              connection
	                                  .createStatement()
	                                  .executeQuery(
	                                      "SELECT key FROM jwt_keys WHERE id = '" + kid + "'");
	                          while (rs.next()) {
	                            return TextCodec.BASE64.decode(rs.getString(1));
	                          }
	                        } catch (SQLException e) {
	                          errorMessage[0] = e.getMessage();
	                        }
	                        return null;
	                      }
	                    })
	                .parseClaimsJws(token);
	        if (errorMessage[0] != null) {
	          return failed(this).output(errorMessage[0]).build();
	        }
	        Claims claims = (Claims) jwt.getBody();
	        String username = (String) claims.get("username");
	        if ("Jerry".equals(username)) {
	          return failed(this).feedback("jwt-final-jerry-account").build();
	        }
	        if ("Tom".equals(username)) {
	          return success(this).build();
	        } else {
	          return failed(this).feedback("jwt-final-not-tom").build();
	        }
	      } catch (JwtException e) {
	        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
	      }
	    }
  }
}
