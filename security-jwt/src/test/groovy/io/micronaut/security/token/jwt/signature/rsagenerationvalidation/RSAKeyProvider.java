package io.micronaut.security.token.jwt.signature.rsagenerationvalidation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.micronaut.context.annotation.Requires;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.inject.Singleton;

@Requires(property = "spec.name", pattern = "rsajwtbooks|rsajwtgateway")
@Singleton
public class RSAKeyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(RSAKeyProvider.class);

    private RSAKey rsaJWK;

    @PostConstruct
    void initialize() {
        try {
            this.rsaJWK = new RSAKeyGenerator(2048)
                    .keyID("123")
                    .generate();
        } catch (JOSEException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error(e.getMessage());
            }
        }
    }

    public RSAKey getRsaJWK() {
        return rsaJWK;
    }
}
