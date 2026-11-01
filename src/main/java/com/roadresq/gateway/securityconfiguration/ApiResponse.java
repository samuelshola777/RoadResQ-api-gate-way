package com.roadresq.gateway.securityconfiguration;

import lombok.Builder;

@Builder
public record ApiResponse(
        boolean success,
        String message,
        Object data
) {
}
