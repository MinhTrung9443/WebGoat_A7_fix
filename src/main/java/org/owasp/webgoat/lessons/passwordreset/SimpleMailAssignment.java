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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.owasp.webgoat.container.users.WebGoatUser;

@RestController
public class SimpleMailAssignment implements AssignmentEndpoint {

    private final String webWolfURL;
    private final RestTemplate restTemplate;
    private final UserRepository userRepository;

    @Autowired
    public SimpleMailAssignment(RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL,
            UserRepository userRepository) {
        this.restTemplate = restTemplate;
        this.webWolfURL = webWolfURL;
        this.userRepository = userRepository;
    }

    @PostMapping(path = "/PasswordReset/simple-mail", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public AttackResult login(@RequestParam String email, @RequestParam String password,
            @CurrentUsername String webGoatUsername) {

        String emailAddress = ofNullable(email).orElse("unknown@webgoat.org");
        String username = extractUsername(emailAddress);

        if (username == null) {
            return failed(this).feedback("password-reset-simple.invalid_email").feedbackArgs(emailAddress).build();
        }

        if (username.equals(webGoatUsername) && StringUtils.reverse(username).equals(password)) {
            return success(this).build();
        } else {
            return failed(this).feedback("password-reset-simple.password_incorrect").feedbackArgs(emailAddress).build();
        }
    }

    @PostMapping(path = "/PasswordReset/simple-mail/reset", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public AttackResult resetPassword(@RequestParam String emailReset, @CurrentUsername String username) {
        String email = ofNullable(emailReset).orElse("unknown@webgoat.org");
        return sendEmail(extractUsername(email), email, username);
    }

    private String extractUsername(String email) {
        // Check if email ends with @webgoat.org
        if (!email.endsWith("@webgoat.org")) {
            return null; // Invalid email domain
        }

        // Extract username (part before @)
        int index = email.indexOf("@");
        if (index == -1) {
            return null; // No @ found, invalid email
        }

        String username = email.substring(0, index);
        // Validate username: non-empty and contains only allowed characters
        if (username.isEmpty() || !isValidUsername(username)) {
            return null; // Invalid username
        }

        return username;
    }

    private boolean isValidUsername(String username) {
        // Allow letters, numbers, dots, and underscores
        return username.matches("^[a-zA-Z0-9._]+$");
    }

    private AttackResult sendEmail(String username, String fullEmail, String currentUser) {
        // If username is null, email was invalid
        if (username == null) {
            return informationMessage(this).feedback("password-reset-simple.invalid_email")
                    .feedbackArgs(fullEmail).build();
        }

        WebGoatUser user = userRepository.findByUsername(username);

        if (user == null || !user.getUsername().equalsIgnoreCase(username)) {
            return informationMessage(this).feedback("password-reset-simple.user_not_found")
                    .feedbackArgs(fullEmail).build();
        }

        // Send email simulation to WebWolf
        try {
            Map<String, String> body = new HashMap<>();
            body.put("email", fullEmail);
            body.put("username", username);
            body.put("content", "Hello " + username + ", someone requested a password reset for your account at "
                    + LocalDateTime.now() + ". If this was you, please follow the instructions...");

            restTemplate.postForObject(webWolfURL, body, String.class);

            return success(this).feedback("password-reset-simple.email_sent").build();
        } catch (RestClientException ex) {
            return failed(this).feedback("password-reset-simple.email_failed").feedbackArgs(ex.getMessage()).build();
        }
    }
}