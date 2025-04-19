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
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

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

    // Phương thức kiểm tra và lấy khóa công khai
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        // Lấy giá trị "jku" từ header JWT
        String jku = (String) header.get("jku");

        // Kiểm tra nếu jku không phải là URL hợp lệ
        if (jku == null || !jku.equals("https://cognito-idp.us-east-1.amazonaws.com/webgoat/.well-known/jwks.json")) {
            throw new JwtException("JKU không hợp lệ: " + jku);
        }

        // Nếu jku hợp lệ, lấy public key từ kid
        String kid = header.getKeyId();
        try {
            RSAPublicKey publicKey = getPublicKeyFromDatabase(kid);
            return publicKey;
        } catch (Exception e) {
            throw new RuntimeException("Không thể giải mã public key từ kid: " + kid, e);
        }
    }

    private RSAPublicKey getPublicKeyFromDatabase(String kid) {
        String sql = "SELECT public_key FROM jwt_keys WHERE kid = ?";
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement(sql)) {

            statement.setString(1, kid);
            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                String publicKeyBase64 = rs.getString("public_key");
                byte[] keyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64);
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");

                return (RSAPublicKey) kf.generatePublic(spec);
            } else {
                throw new IllegalArgumentException("Không tìm thấy khóa với kid: " + kid);
            }

        } catch (SQLException | java.security.NoSuchAlgorithmException | java.security.spec.InvalidKeySpecException e) {
            throw new RuntimeException("Lỗi khi lấy khóa công khai từ DB", e);
        }
    }

    @PostMapping("jku/delete")
    public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
        if (StringUtils.isEmpty(token)) {
            return failed(this).feedback("jwt-invalid-token").build();
        } else {
            try {
                final String[] errorMessage = {null};

                Jwt jwt = Jwts.parser()
                        .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                            @Override
                            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                                // Kiểm tra lại jku khi giải mã token
                                String jku = (String) header.get("jku");
                                if (jku == null || !jku.equals("https://cognito-idp.us-east-1.amazonaws.com/webgoat/.well-known/jwks.json")) {
                                    errorMessage[0] = "JKU không hợp lệ: " + jku;
                                    return null;  // Trả về null nếu JKU không hợp lệ
                                }
                                String kid = header.getKeyId();
                                return getPublicKeyFromDatabase(kid);
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

