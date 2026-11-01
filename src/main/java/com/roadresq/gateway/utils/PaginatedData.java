package com.roadresq.gateway.utils;

import lombok.Builder;

@Builder
public record PaginatedData(

        int totalPage,
        int pageNumber,
        int numberOfElements,
        long totalElements,
        boolean last,
        Object data
) {
}
