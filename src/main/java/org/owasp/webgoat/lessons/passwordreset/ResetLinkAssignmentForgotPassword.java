/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

    private final RestTemplate restTemplate;
    private final String webWolfMailURL;
    private final String baseDomainURL;

    public ResetLinkAssignmentForgotPassword(
            RestTemplate restTemplate,
            @Value("${webwolf.mail.url}") String webWolfMailURL,
            @Value("${webgoat.base-url}") String baseDomainURL) {
        this.restTemplate = restTemplate;
        this.webWolfMailURL = webWolfMailURL;
        this.baseDomainURL = baseDomainURL;
    }

    @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
    @ResponseBody
    public AttackResult sendPasswordResetLink(
            @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {

        // Tạo reset token
        String resetLink = UUID.randomUUID().toString();
        ResetLinkAssignment.resetLinks.add(resetLink);

        try {
            sendMailToUser(email, resetLink);
        } catch (Exception e) {
            return failed(this).output("E-mail can't be sent. Please try again.").build();
        }

        return success(this).feedback("email.send").feedbackArgs(email).build();
    }

    private void sendMailToUser(String email, String resetLink) {
        int index = email.indexOf("@");
        String username = email.substring(0, index == -1 ? email.length() : index);

        PasswordResetEmail mail = PasswordResetEmail.builder()
                .title("Your password reset link")
                .contents(String.format(ResetLinkAssignment.TEMPLATE, baseDomainURL, resetLink))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .build();

        this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
    }
}