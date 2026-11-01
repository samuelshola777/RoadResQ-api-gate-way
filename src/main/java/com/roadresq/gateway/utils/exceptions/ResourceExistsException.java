package com.roadresq.gateway.utils.exceptions;

public class ResourceExistsException extends RuntimeException{
    public ResourceExistsException(String message){
        super(message);
    }
}
