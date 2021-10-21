package com.example.springsecurityoauth2.entity;

import com.example.springsecurityoauth2.entity.type.AuthProvider;
import lombok.*;

import javax.persistence.Embeddable;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import java.util.Map;

@Getter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class SocialAuth {
    private String providerId;
    @Enumerated(value = EnumType.STRING)
    private AuthProvider provider;
    private String email;
    private String name;
    private String imageUrl;
    private String attributes;
    private String ip;

    public void update(String name, String imageUrl, Map<String, Object> attributes) {
        this.name = name;
        this.imageUrl = imageUrl;
        this.attributes = attributes.toString();
    }

}
