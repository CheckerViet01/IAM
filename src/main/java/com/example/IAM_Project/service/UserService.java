package com.example.IAM_Project.service;

import com.example.IAM_Project.dto.*;
import com.example.IAM_Project.entity.User;
import com.example.IAM_Project.entity.UserActivityLog;
import com.example.IAM_Project.entity.UserAvatar;
import com.example.IAM_Project.entity.VerificationToken;
import com.example.IAM_Project.exception.BadRequestException;
import com.example.IAM_Project.exception.ResourceNotFoundException;
import com.example.IAM_Project.repository.UserActivityLogRepository;
import com.example.IAM_Project.repository.UserAvatarRepository;
import com.example.IAM_Project.repository.UserRepository;
import com.example.IAM_Project.repository.VerificationTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserAvatarRepository userAvatarRepository;
    private final UserActivityLogRepository activityLogRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthService authService;
    private final FileStorageService fileStorageService;
    private final MailService mailService;
    private final RedisService redisService;
    private final ActivityLogService activityLogService;

    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));
        return authService.mapToProfileResponse(user);
    }

    @Transactional
    public UserProfileResponse updateProfile(String email, UpdateProfileRequest request, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        if (request.getFullName() != null) {
            user.setFullName(request.getFullName().trim());
        }
        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber().trim());
        }
        if (request.getAddress() != null) {
            user.setAddress(request.getAddress().trim());
        }
        if (request.getDateOfBirth() != null) {
            user.setDateOfBirth(request.getDateOfBirth());
        }
        if (request.getGender() != null) {
            user.setGender(request.getGender().trim());
        }

        user.setUpdatedAt(LocalDateTime.now());
        User savedUser = userRepository.save(user);

        // Gửi email thông báo cập nhật hồ sơ
        try {
            mailService.sendProfileUpdatedAlert(savedUser);
        } catch (Exception ignored) {}

        activityLogService.log(savedUser, email, "UPDATE_PROFILE", "SUCCESS", httpRequest, "Cập nhật thông tin cá nhân");

        return authService.mapToProfileResponse(savedUser);
    }

    @Transactional
    public ApiResponse<String> changePassword(String email, ChangePasswordRequest request, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPasswordHash())) {
            activityLogService.log(user, email, "CHANGE_PASSWORD", "FAILED", httpRequest, "Mật khẩu cũ không chính xác");
            throw new BadRequestException("Mật khẩu hiện tại không chính xác!");
        }

        if (request.getOldPassword().equals(request.getNewPassword())) {
            throw new BadRequestException("Mật khẩu mới không được trùng với mật khẩu cũ!");
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Mật khẩu mới và xác nhận mật khẩu không khớp!");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Gửi email cảnh báo đổi mật khẩu
        try {
            mailService.sendPasswordChangedAlert(user);
        } catch (Exception ignored) {}

        activityLogService.log(user, email, "CHANGE_PASSWORD", "SUCCESS", httpRequest, "Đổi mật khẩu thành công");

        return ApiResponse.ok("Đổi mật khẩu thành công! Hãy sử dụng mật khẩu mới cho các lần đăng nhập tiếp theo.");
    }

    @Transactional
    public ApiResponse<String> uploadAvatar(String email, MultipartFile file, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        String avatarUrl = fileStorageService.storeAvatar(file, user);
        user.setAvatarUrl(avatarUrl);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        activityLogService.log(user, email, "UPLOAD_AVATAR", "SUCCESS", httpRequest, "Cập nhật ảnh đại diện mới");

        return ApiResponse.ok("Cập nhật ảnh đại diện thành công!", avatarUrl);
    }

    @Transactional(readOnly = true)
    public List<AvatarResponse> getUserAvatars(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        List<UserAvatar> avatars = userAvatarRepository.findByUserOrderByUploadedAtDesc(user);
        return avatars.stream().map(a -> AvatarResponse.builder()
                .id(a.getId())
                .fileName(a.getFileName())
                .originalFileName(a.getOriginalFileName())
                .fileUrl(a.getFilePathOrUrl())
                .fileSizeBytes(a.getFileSizeBytes())
                .isCurrent(a.getIsCurrent())
                .uploadedAt(a.getUploadedAt())
                .build()
        ).collect(Collectors.toList());
    }

    @Transactional
    public ApiResponse<String> requestEnable2fa(String email, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        if (Boolean.TRUE.equals(user.getTwoFactorEnabled())) {
            throw new BadRequestException("Tính năng xác thực hai yếu tố (2FA) đã được kích hoạt trên tài khoản này!");
        }

        String otp = authService.generateNumericOtp(6);
        redisService.storeOtp(email, otp, 10);

        VerificationToken token = VerificationToken.builder()
                .user(user)
                .tokenCode(otp)
                .tokenType("TWO_FACTOR_OTP")
                .deliveryChannel("EMAIL")
                .destination(email)
                .attempts(0)
                .maxAttempts(5)
                .expiresAt(LocalDateTime.now().plusMinutes(10))
                .isUsed(false)
                .createdAt(LocalDateTime.now())
                .build();
        verificationTokenRepository.save(token);

        mailService.sendOtpEmail(user, email, otp, "Kích hoạt xác thực 2 bước (2FA)", "TWO_FACTOR_OTP");
        activityLogService.log(user, email, "REQUEST_ENABLE_2FA", "SUCCESS", httpRequest, "Gửi mã OTP yêu cầu bật 2FA");

        return ApiResponse.ok("Mã xác nhận OTP đã được gửi đến email của bạn để xác nhận bật 2FA.");
    }

    @Transactional
    public ApiResponse<String> confirmEnable2fa(String email, String otpCode, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        String cachedOtp = redisService.getOtp(email);
        boolean isValid = false;

        if (cachedOtp != null && cachedOtp.equals(otpCode.trim())) {
            isValid = true;
            redisService.deleteOtp(email);
        } else {
            var tokenOpt = verificationTokenRepository.findFirstByUserAndTokenTypeAndIsUsedFalseOrderByCreatedAtDesc(user, "TWO_FACTOR_OTP");
            if (tokenOpt.isPresent()) {
                VerificationToken token = tokenOpt.get();
                if (token.getExpiresAt().isAfter(LocalDateTime.now()) && token.getTokenCode().equals(otpCode.trim())) {
                    isValid = true;
                    token.setIsUsed(true);
                    token.setUsedAt(LocalDateTime.now());
                    verificationTokenRepository.save(token);
                }
            }
        }

        if (!isValid) {
            activityLogService.log(user, email, "CONFIRM_ENABLE_2FA", "FAILED", httpRequest, "Mã OTP bật 2FA sai hoặc đã hết hạn");
            throw new BadRequestException("Mã OTP không chính xác hoặc đã hết hạn!");
        }

        user.setTwoFactorEnabled(true);
        user.setTwoFactorMethod("EMAIL");
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        activityLogService.log(user, email, "ENABLE_2FA", "SUCCESS", httpRequest, "Kích hoạt thành công 2FA bằng Email OTP");

        return ApiResponse.ok("Đã kích hoạt xác thực 2 yếu tố (2FA) thành công! Mỗi lần đăng nhập sẽ yêu cầu mã OTP gửi qua email.");
    }

    @Transactional
    public ApiResponse<String> disable2fa(String email, String password, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            activityLogService.log(user, email, "DISABLE_2FA", "FAILED", httpRequest, "Mật khẩu xác nhận tắt 2FA không chính xác");
            throw new BadRequestException("Mật khẩu không chính xác!");
        }

        user.setTwoFactorEnabled(false);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        activityLogService.log(user, email, "DISABLE_2FA", "SUCCESS", httpRequest, "Hủy kích hoạt 2FA thành công");

        return ApiResponse.ok("Đã tắt xác thực hai yếu tố (2FA) thành công.");
    }

    @Transactional(readOnly = true)
    public Page<ActivityLogResponse> getUserActivityLogs(String email, Pageable pageable) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Người dùng không tồn tại"));

        Page<UserActivityLog> page = activityLogRepository.findByUserOrderByCreatedAtDesc(user, pageable);
        return page.map(log -> ActivityLogResponse.builder()
                .id(log.getId())
                .action(log.getAction())
                .status(log.getStatus())
                .ipAddress(log.getIpAddress())
                .userAgent(log.getUserAgent())
                .details(log.getDetails())
                .createdAt(log.getCreatedAt())
                .build()
        );
    }
}
