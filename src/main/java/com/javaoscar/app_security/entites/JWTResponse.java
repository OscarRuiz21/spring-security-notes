package com.javaoscar.app_security.entites;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JWTResponse {

    private String jwt;
}
