/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class QuestionsAssignment implements AssignmentEndpoint {
    // Di chuyển dữ liệu nhạy cảm ra khỏi mã nguồn
    // Trong thực tế, nên lưu trữ câu hỏi và đáp án bảo mật trong cơ sở dữ liệu với mã hóa thích hợp
    private final UserSecurityQuestionService securityQuestionService;

    // Rate limiting để ngăn chặn tấn công brute force
    private final Map<String, AttemptTracker> loginAttempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 3;
    private static final long LOCKOUT_TIME_MS = 15 * 60 * 1000; // 15 phút

    @Autowired
    public QuestionsAssignment(UserSecurityQuestionService securityQuestionService) {
        this.securityQuestionService = securityQuestionService;
    }

    @PostMapping(
            path = "/PasswordReset/questions",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    public AttackResult passwordReset(@RequestParam Map<String, Object> json, HttpServletRequest request) {
        String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
        String username = (String) json.getOrDefault("username", "");
        String clientIP = request.getRemoteAddr();

        // Kiểm tra giới hạn số lần thử
        AttemptTracker tracker = loginAttempts.computeIfAbsent(
                clientIP, k -> new AttemptTracker());

        if (tracker.isLocked()) {
            return failed(this)
                    .feedback("too-many-attempts")
                    .build();
        }

        // Kiểm tra nếu username trống
        if (username.trim().isEmpty()) {
            return failed(this)
                    .feedback("username-required")
                    .build();
        }

        // Kiểm tra nếu câu trả lời trống
        if (securityQuestion.trim().isEmpty()) {
            return failed(this)
                    .feedback("security-answer-required")
                    .build();
        }

        // Kiểm tra hợp lệ - sử dụng thông báo lỗi chung để tránh username enumeration
        boolean isValid = securityQuestionService.validateSecurityQuestion(username, securityQuestion);

        if (isValid) {
            // Reset số lần thử khi thành công
            tracker.resetAttempts();
            return success(this).build();
        } else {
            // Tăng số lần thử và trả về lỗi chung
            tracker.incrementAttempts();
            return failed(this)
                    .feedback("invalid-username-or-answer")
                    .build();
        }
    }

    // Class theo dõi số lần thử đăng nhập
    private static class AttemptTracker {
        private int attempts = 0;
        private long lockedUntil = 0;

        public void incrementAttempts() {
            attempts++;
            if (attempts >= MAX_ATTEMPTS) {
                lockedUntil = System.currentTimeMillis() + LOCKOUT_TIME_MS;
            }
        }

        public boolean isLocked() {
            if (System.currentTimeMillis() < lockedUntil) {
                return true;
            } else if (lockedUntil > 0) {
                // Reset sau thời gian khóa
                attempts = 0;
                lockedUntil = 0;
            }
            return false;
        }

        public void resetAttempts() {
            attempts = 0;
            lockedUntil = 0;
        }
    }
}

// Interface đề xuất cho service xử lý câu hỏi bảo mật
interface UserSecurityQuestionService {
    /**
     * Xác thực câu trả lời cho câu hỏi bảo mật của người dùng
     * @param username tên người dùng
     * @param answer câu trả lời
     * @return true nếu câu trả lời chính xác
     */
    boolean validateSecurityQuestion(String username, String answer);
}

// Triển khai thực tế của service
@Service
class UserSecurityQuestionServiceImpl implements UserSecurityQuestionService {

    // Mô phỏng cơ sở dữ liệu - trong thực tế sẽ lưu vào DB với mã hóa
    private final Map<String, UserSecurityInfo> userSecurityInfo;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserSecurityQuestionServiceImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        userSecurityInfo = new HashMap<>();
        // Thêm dữ liệu mẫu - trong thực tế sẽ được lấy từ DB
        userSecurityInfo.put("admin", new UserSecurityInfo("admin", passwordEncoder.encode("green")));
        userSecurityInfo.put("jerry", new UserSecurityInfo("jerry", passwordEncoder.encode("orange")));
        userSecurityInfo.put("tom", new UserSecurityInfo("tom", passwordEncoder.encode("purple")));
        userSecurityInfo.put("larry", new UserSecurityInfo("larry", passwordEncoder.encode("yellow")));
        userSecurityInfo.put("webgoat", new UserSecurityInfo("webgoat", passwordEncoder.encode("red")));
    }

    @Override
    public boolean validateSecurityQuestion(String username, String answer) {
        // Thời gian thực thi cố định để tránh timing attacks
        UserSecurityInfo userInfo = userSecurityInfo.get(username.toLowerCase());

        // Sử dụng thời gian thực thi không đổi để tránh timing attacks
        boolean isValid = false;
        if (userInfo != null) {
            isValid = passwordEncoder.matches(answer, userInfo.getEncodedAnswer());
        }

        // Thêm delay cố định để tránh timing attacks
        try {
            Thread.sleep(300);  // 300ms delay
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return isValid;
    }

    // Lớp chứa thông tin bảo mật của người dùng
    private static class UserSecurityInfo {
        private final String username;
        private final String encodedAnswer;

        public UserSecurityInfo(String username, String encodedAnswer) {
            this.username = username;
            this.encodedAnswer = encodedAnswer;
        }

        public String getEncodedAnswer() {
            return encodedAnswer;
        }
    }
}
