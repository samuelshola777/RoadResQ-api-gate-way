package com.roadresq.gateway.utils.exceptions;

import com.roadresq.gateway.utils.ApiResponse;
import com.roadresq.gateway.utils.PaginatedData;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ServerWebInputException;

import java.io.IOException;
import java.net.ConnectException;
import java.time.LocalDateTime;
import java.util.Map;

@ControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse> handleJsonParseError(
            HttpMessageNotReadableException ex
    ) {
        String message =
                "Invalid JSON request. A required field might be missing "
                        + "or incorrectly formatted (" + ex.getMessage() + ")";

        return new ResponseEntity<>(
                new ApiResponse(false, message, null),
                HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public final ResponseEntity<ApiResponse> handleValidationException(
            MethodArgumentNotValidException ex
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, ex.getMessage(), null),
                HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public final ResponseEntity<ApiResponse> handleMissingRequestParameterException(
            IllegalArgumentException ex
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, ex.getMessage(), null),
                HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(ServerWebInputException.class)
    public final ResponseEntity<ApiResponse> handleBadRequestException(
            ServerWebInputException ex
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, ex.getMessage(), null),
                HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(ResourceExistsException.class)
    public final ResponseEntity<ApiResponse> handleResourceExistsException(
            ResourceExistsException exception
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, exception.getMessage(), null),
                HttpStatus.CONFLICT
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public final ResponseEntity<ApiResponse> handleResourceNotFoundException(
            ResourceNotFoundException exception
    ) {
        if (exception.isReturn404()) {
            return new ResponseEntity<>(
                    new ApiResponse(false, exception.getMessage(), null),
                    HttpStatus.NOT_FOUND
            );
        }

        if (exception.isPaginated()) {
            return ResponseEntity.ok(
                    new ApiResponse(
                            true,
                            exception.getMessage(),
                            new PaginatedData(
                                    0, 0, 0, 0, false, new Object[0]
                            )
                    )
            );
        }

        return ResponseEntity.ok(
                new ApiResponse(true, exception.getMessage(), null)
        );
    }

    @ExceptionHandler(UnauthorizedException.class)
    public final ResponseEntity<ApiResponse> handleUnauthorizedException(
            UnauthorizedException exception
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, exception.getMessage(), null),
                HttpStatus.UNAUTHORIZED
        );
    }

    @ExceptionHandler(InvalidOperationException.class)
    public final ResponseEntity<ApiResponse> handleInvalidOperationException(
            InvalidOperationException exception
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, exception.getMessage(), null),
                HttpStatus.FORBIDDEN
        );
    }

    @ExceptionHandler(InvalidInputException.class)
    public final ResponseEntity<ApiResponse> handleInvalidInputException(
            InvalidInputException exception
    ) {
        if (exception.getErrorData() == null) {
            return new ResponseEntity<>(
                    new ApiResponse(false, exception.getMessage(), null),
                    HttpStatus.BAD_REQUEST
            );
        }

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .header(
                        "Content-Disposition",
                        "attachment; filename=\"errorReport.txt\""
                )
                .body(
                        new ApiResponse(
                                false,
                                exception.getMessage(),
                                exception.getErrorData()
                        )
                );
    }

    @ExceptionHandler(ConnectException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Map<String, Object> handleConnectException(ConnectException ex) {
        return Map.of(
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "error", "Service Unavailable",
                "message",
                "service is currently unavailable. Please try again later."
        );
    }

    @ExceptionHandler(IOException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public Map<String, Object> handleIOException(IOException ex) {
        return Map.of(
                "timestamp", LocalDateTime.now(),
                "status", HttpStatus.BAD_GATEWAY.value(),
                "error", "Bad Gateway",
                "message", "Unable to connect to  server."
        );
    }

    @ExceptionHandler(ErrorProcessingRequestException.class)
    public final ResponseEntity<ApiResponse> handleErrorProcessingRequestException(
            ErrorProcessingRequestException exception
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, exception.getMessage(), null),
                HttpStatus.INTERNAL_SERVER_ERROR
        );
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public final ResponseEntity<ApiResponse> handleUnsupportedOperationException(
            UnsupportedOperationException exception
    ) {
        return new ResponseEntity<>(
                new ApiResponse(false, exception.getMessage(), null),
                HttpStatus.NOT_ACCEPTABLE
        );
    }
}