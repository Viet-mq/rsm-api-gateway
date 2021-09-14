package com.edso.resume.gw.repo;

import com.edso.resume.gw.entities.SessionEntity;
import com.edso.resume.lib.exception.SessionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

@Repository
public class SessionRepository {

    @Value("${app.session.timeout:900000}")
    private long timeout;

    private final SessionEntityRepo sessionEntityRepo;

    public SessionRepository(SessionEntityRepo sessionEntityRepo) {
        this.sessionEntityRepo = sessionEntityRepo;
    }

    public synchronized SessionEntity getSession(String token) throws SessionException {
        SessionEntity sessionEntity = sessionEntityRepo.findById(token).orElse(null);
        if (sessionEntity == null) {
            throw new SessionException("Session not existed -> login again");
        }
        if (sessionEntity.getLastRequest() + (timeout * 60 * 1000) < System.currentTimeMillis()) {
            throw new SessionException("Session has been expired -> login again");
        }
        if (sessionEntity.getNeedToDie()) {
            throw new SessionException("Session has been killed -> login again");
        }
        sessionEntity.setLastRequest(System.currentTimeMillis());
        return sessionEntity;
    }

}
