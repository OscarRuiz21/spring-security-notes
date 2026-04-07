package com.javaoscar.app_security.repositories;

import com.javaoscar.app_security.entites.PartnerEntity;
import org.springframework.data.repository.CrudRepository;

import java.math.BigInteger;
import java.util.Optional;

public interface PartnerRepository extends CrudRepository<PartnerEntity, BigInteger> {

    Optional<PartnerEntity>findByClientId(String clientId);
}