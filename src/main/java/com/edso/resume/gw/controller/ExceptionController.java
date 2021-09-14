package com.edso.resume.gw.controller;

import com.edso.resume.lib.exception.ServerException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

@ControllerAdvice
public class ExceptionController {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleConstraintViolation(ServerException ex, WebRequest request) {
        return new ResponseEntity<>("Custom Error", new HttpHeaders(), HttpStatus.OK);
    }
}
