/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static java.util.Optional.ofNullable;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.UserRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RestController
public class SimpleMailAssignment implements AssignmentEndpoint {

    private final String webWolfURL;
    private final RestTemplate restTemplate;
    private final UserRepository userRepository;

    @Autowired
    public SimpleMailAssignment(RestTemplate restTemplate,
                                @Value("${webwolf.mail.url}") String webWolfURL,
                                UserRepository userRepository) {
        this.restTemplate = restTemplate;
        this.webWolfURL = webWolfURL;
        this.userRepository = userRepository;
    }

    @PostMapping(
            path = "/PasswordReset/simple-mail",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public AttackResult login(@RequestParam String email,
                              @RequestParam String password,
                              @CurrentUsername String webGoatUsername) {

        String emailAddress = ofNullable(email).orElse("unknown@webgoat.org");
        String username = extractUsername(emailAddress);

        if (username.equals(webGoatUsername) && StringUtils.reverse(username).equals(password)) {
            return success(this).build();
        } else {
            return failed(this)
                    .feedback("password-reset-simple.password_incorrect")
                    .feedbackArgs(email)
                    .build();
        }
    }

    @PostMapping(
            path = "/PasswordReset/simple-mail/reset",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public AttackResult resetPassword(@RequestParam String emailReset,
                                      @CurrentUsername String username) {
        String email = ofNullable(emailReset).orElse("unknown@webgoat.org");
        return sendEmail(extractUsername(email), email, username);
    }

    private String extractUsername(String email) {
        int index = email.indexOf("@");
        return email.substring(0, index == -1 ? email.length() : index);
    }

    private AttackResult sendEmail(String email, String fullEmail, String currentUser) {
        WebGoatUser user = userRepository.findByUsername(email);

        if (user == null || !user.getUsername().equalsIgnoreCase(fullEmail)) {
            return informationMessage(this)
                    .feedback("password-reset-simple.user_not_found_or_email_mismatch")
                    .feedbackArgs(fullEmail)
                    .build();
        }

        // Gửi email mô phỏng đến WebWolf
        try {
            Map<String, String> body = new HashMap<>();
            body.put("email", fullEmail);
            body.put("username", email);
            body.put("content", "Hello " + email + ", someone requested a password reset for your account at "
                    + LocalDateTime.now() + ". If this was you, please follow the instructions...");

            restTemplate.postForObject(webWolfURL, body, String.class);

            return success(this)
                    .feedback("password-reset-simple.email_sent")
                    .build();
        } catch (RestClientException ex) {
            return failed(this)
                    .feedback("password-reset-simple.email_failed")
                    .feedbackArgs(ex.getMessage())
                    .build();
        }
    }
}
