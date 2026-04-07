package com.javaoscar.app_security.entites;

import lombok.Data;

@Data
public class JWTRequest {

    private String username;
    private String password;
}
