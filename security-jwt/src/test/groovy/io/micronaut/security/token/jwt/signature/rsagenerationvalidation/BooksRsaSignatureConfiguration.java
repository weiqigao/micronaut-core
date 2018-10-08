package io.micronaut.security.token.jwt.signature.rsagenerationvalidation;

import com.nimbusds.jose.JOSEException;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration;

import javax.inject.Singleton;
import java.security.interfaces.RSAPublicKey;

@Requires(property = "spec.name", value = "rsajwtbooks")
@Singleton
public class BooksRsaSignatureConfiguration implements RSASignatureConfiguration {

    private final RSAPublicKey rsaPublicKey;

    public BooksRsaSignatureConfiguration(RSAKeyProvider rsaKeyProvider) throws JOSEException {
        this.rsaPublicKey = rsaKeyProvider.getRsaJWK().toRSAPublicKey();
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return this.rsaPublicKey;
    }
}
