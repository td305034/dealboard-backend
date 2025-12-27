package com.td.dealboard.auth;

import lombok.Data;

@Data
public class GoogleTokenResponse {
    private String access_token;
    private String refresh_token;
    private String id_token;
    private String scope;
    private int expires_in;
}
