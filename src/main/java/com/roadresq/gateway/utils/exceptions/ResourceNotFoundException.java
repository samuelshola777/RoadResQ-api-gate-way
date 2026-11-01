package com.roadresq.gateway.utils.exceptions;


public class ResourceNotFoundException extends RuntimeException {

    private final boolean return404;
    private final boolean paginated;

    public ResourceNotFoundException(String message, boolean return404, boolean paginated) {
        super(message);
        this.return404 = return404;
        this.paginated = paginated;
    }

    public boolean isReturn404() {
        return return404;
    }

    public boolean isPaginated() {
        return paginated;
    }
}
