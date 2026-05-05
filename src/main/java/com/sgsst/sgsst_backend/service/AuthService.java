package com.sgsst.sgsst_backend.service;

import com.sgsst.sgsst_backend.dto.request.AuthRequest;
import com.sgsst.sgsst_backend.dto.request.RegisterRequest;
import com.sgsst.sgsst_backend.dto.response.AuthResponse;
import com.sgsst.sgsst_backend.dto.response.MeResponse;
import com.sgsst.sgsst_backend.entity.Role;
import com.sgsst.sgsst_backend.entity.Usuario;
import com.sgsst.sgsst_backend.repository.UsuarioRepository;
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

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        final String normalizedEmail = normalizeEmail(request.email());

        if (usuarioRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Ya existe un usuario registrado con ese correo");
        }

        if (request.role() == Role.ADMIN) {
            throw new IllegalArgumentException("No se permite registrar administradores desde este endpoint");
        }

        final Usuario usuario = Usuario.builder()
                .nombreCompleto(request.nombreCompleto().trim())
                .email(normalizedEmail)
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .active(true)
                .failedLoginAttempts(0)
                .build();

        final Usuario savedUsuario = usuarioRepository.save(usuario);
        return buildAuthResponse(savedUsuario);
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        final Usuario usuario = findUsuarioByEmail(request.email());
        validateActiveUsuario(usuario);
        validateUnlockedUsuario(usuario);

        if (!passwordEncoder.matches(request.password(), usuario.getPassword())) {
            registerFailedAttempt(usuario);
            throw new BadCredentialsException("Credenciales inválidas");
        }

        resetFailedAttempts(usuario);
        return buildAuthResponse(usuario);
    }

    @Transactional(readOnly = true)
    public MeResponse me(Authentication authentication) {
        final Usuario usuario = (Usuario) authentication.getPrincipal();
        return new MeResponse(
                usuario.getId(),
                usuario.getNombreCompleto(),
                usuario.getEmail(),
                usuario.getRole(),
                usuario.isEnabled()
        );
    }

    private Usuario findUsuarioByEmail(String email) {
        final String normalizedEmail = normalizeEmail(email);
        return usuarioRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));
    }

    private void validateActiveUsuario(Usuario usuario) {
        if (!Boolean.TRUE.equals(usuario.getActive())) {
            throw new DisabledException("Tu usuario se encuentra inactivo");
        }
    }

    private void validateUnlockedUsuario(Usuario usuario) {
        if (usuario.isTemporarilyLocked()) {
            throw new LockedException("Tu usuario está bloqueado temporalmente. Intenta más tarde");
        }
    }

    private AuthResponse buildAuthResponse(Usuario usuario) {
        final String token = jwtService.generateToken(usuario);
        return new AuthResponse(
                token,
                "Bearer",
                usuario.getId(),
                usuario.getNombreCompleto(),
                usuario.getEmail(),
                usuario.getRole()
        );
    }

    private void registerFailedAttempt(Usuario usuario) {
        final int attempts = usuario.getFailedLoginAttempts() + 1;
        usuario.setFailedLoginAttempts(attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            usuario.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
            usuario.setFailedLoginAttempts(0);
        }

        usuarioRepository.save(usuario);
    }

    private void resetFailedAttempts(Usuario usuario) {
        usuario.setFailedLoginAttempts(0);
        usuario.setLockedUntil(null);
        usuarioRepository.save(usuario);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
