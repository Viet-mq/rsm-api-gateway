package com.edso.resume.gw.repo;

import com.edso.resume.gw.entities.SessionEntity;
import org.springframework.data.repository.CrudRepository;

public interface SessionEntityRepo extends CrudRepository<SessionEntity, String> {
}
