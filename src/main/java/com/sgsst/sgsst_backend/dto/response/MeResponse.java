package com.sgsst.sgsst_backend.dto.response;

import com.sgsst.sgsst_backend.entity.Role;

public record MeResponse(
        Long id,
        String nombreCompleto,
        String email,
        Role role,
        boolean active
) {
}
