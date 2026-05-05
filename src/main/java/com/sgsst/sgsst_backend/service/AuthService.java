package com.sgsst.sgsst_backend.service;

import com.sgsst.sgsst_backend.dto.request.AuthRequest;
import com.sgsst.sgsst_backend.dto.request.RegisterRequest;
import com.sgsst.sgsst_backend.dto.response.AuthResponse;
import com.sgsst.sgsst_backend.dto.response.MeResponse;
import com.sgsst.sgsst_backend.entity.Role;
import com.sgsst.sgsst_backend.entity.User;
import com.sgsst.sgsst_backend.repository.UserRepository;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.email());

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Ya existe un usuario registrado con ese correo");
        }

        if (request.role() == Role.ADMIN) {
            throw new IllegalArgumentException("No se permite registrar administradores desde este endpoint");
        }

        User user = User.builder()
                .nombreCompleto(request.nombreCompleto().trim())
                .email(normalizedEmail)
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .active(true)
                .failedLoginAttempts(0)
                .build();

        User savedUser = userRepository.save(user);
        return buildAuthResponse(savedUser);
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

        if (!Boolean.TRUE.equals(user.getActive())) {
            throw new DisabledException("Tu usuario se encuentra inactivo");
        }

        if (user.isTemporarilyLocked()) {
            throw new LockedException("Tu usuario está bloqueado temporalmente. Intenta más tarde");
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            registerFailedAttempt(user);
            throw new BadCredentialsException("Credenciales inválidas");
        }

        resetFailedAttempts(user);
        return buildAuthResponse(user);
    }

    @Transactional(readOnly = true)
    public MeResponse me(Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        return new MeResponse(
                user.getId(),
                user.getNombreCompleto(),
                user.getEmail(),
                user.getRole(),
                user.isEnabled()
        );
    }

    private AuthResponse buildAuthResponse(User user) {
        String token = jwtService.generateToken(user);
        return new AuthResponse(
                token,
                "Bearer",
                user.getId(),
                user.getNombreCompleto(),
                user.getEmail(),
                user.getRole()
        );
    }

    private void registerFailedAttempt(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
            user.setFailedLoginAttempts(0);
        }

        userRepository.save(user);
    }

    private void resetFailedAttempts(User user) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
