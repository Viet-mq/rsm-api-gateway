package com.edso.resume.gw.jwt;

import com.edso.resume.lib.common.ErrorCodeDefs;
import com.edso.resume.lib.response.BaseResponse;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class AuthResponse extends BaseResponse {

    @JsonIgnore
    private String user;

    @JsonIgnore
    private String key;

    public AuthResponse(String token) {
        code = ErrorCodeDefs.ERROR_CODE_FAILED;
    }

    public void setSuccess() {
        this.code = ErrorCodeDefs.ERROR_CODE_OK;
    }

    public String toJson() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        return "UNKNOWN";
    }

}
