package com.edso.resume.gw.entities;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@RedisHash("SessionEntity")
public class SessionEntity implements Serializable {
    @Id
    private String token;
    private String username;
    private Integer role;
    private List<String> permissions;
    private List<String> organizations;
    private Long lastRequest;
    @Builder.Default
    private Boolean needToDie = false;

}
