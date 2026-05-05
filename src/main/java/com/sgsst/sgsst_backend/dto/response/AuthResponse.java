package com.sgsst.sgsst_backend.dto.response;

import com.sgsst.sgsst_backend.entity.Role;

public record AuthResponse(
        String token,
        String tokenType,
        Long userId,
        String nombreCompleto,
        String email,
        Role role
) {
}
