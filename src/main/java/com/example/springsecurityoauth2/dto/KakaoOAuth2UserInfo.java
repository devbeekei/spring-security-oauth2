package com.example.springsecurityoauth2.dto;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo {

    private Integer id;

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super((Map<String, Object>) attributes.get("kakao_account"));
        this.id = (Integer) attributes.get("id");
    }

    @Override
    public String getId() {
        return this.id.toString();
    }

    @Override
    public String getName() {
        return (String) ((Map<String, Object>) attributes.get("profile")).get("nickname");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) ((Map<String, Object>) attributes.get("profile")).get("thumbnail_image_url");
    }

}
