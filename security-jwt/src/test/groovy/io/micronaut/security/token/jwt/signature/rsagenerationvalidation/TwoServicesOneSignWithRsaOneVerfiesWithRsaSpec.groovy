package io.micronaut.security.token.jwt.signature.rsagenerationvalidation

import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.client.DefaultHttpClientConfiguration
import io.micronaut.http.client.RxHttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.token.jwt.AuthorizationUtils
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureFactory
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise

import java.time.Duration

@Stepwise
class TwoServicesOneSignWithRsaOneVerfiesWithRsaSpec extends Specification implements AuthorizationUtils {

    private final String SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    int booksPort

    @Shared
    EmbeddedServer booksEmbeddedServer

    @Shared
    RxHttpClient booksClient

    @Shared
    EmbeddedServer gatewayEmbeddedServer

    @Shared
    RxHttpClient gatewayClient

    def cleanupSpec() {
        booksEmbeddedServer?.stop()
        booksEmbeddedServer?.close()

        booksClient?.stop()
        booksClient?.close()

        gatewayClient?.stop()
        gatewayClient?.close()

        gatewayEmbeddedServer?.stop()
        gatewayEmbeddedServer?.close()
    }

    def "setup books server"() {
        given:
        booksPort = SocketUtils.findAvailableTcpPort()
        Map booksConfig = [
                (SPEC_NAME_PROPERTY)                          : 'rsajwtbooks',
                'micronaut.server.port'                       : booksPort,
                'micronaut.security.enabled'                  : true,
                'micronaut.security.token.jwt.enabled'        : true,
        ]

        booksEmbeddedServer = ApplicationContext.run(EmbeddedServer, booksConfig, Environment.TEST)

        booksClient = booksEmbeddedServer.applicationContext.createBean(RxHttpClient, booksEmbeddedServer.getURL())

        when:
        booksEmbeddedServer.applicationContext.getBean(SignatureGeneratorConfiguration)

        then:
        thrown(NoSuchBeanException)

        when:
        for (Class beanClazz : [
                BooksRsaSignatureConfiguration,
                RSAKeyProvider,
                BooksController,
                RSASignatureConfiguration,
                RSASignatureFactory,
                SignatureConfiguration
        ]) {
            booksEmbeddedServer.applicationContext.getBean(beanClazz)
        }

        then:
        noExceptionThrown()
    }

    def "setup gateway server"() {
        given:
        Map gatewayConfig = [
                (SPEC_NAME_PROPERTY)                        : 'rsajwtgateway',
                'micronaut.security.enabled'                : true,
                'micronaut.security.token.jwt.enabled'      : true,
                'micronaut.security.endpoints.login.enabled': true,
                'micronaut.http.services.books.url'         : "http://localhost:${booksPort}",
        ]

        gatewayEmbeddedServer = ApplicationContext.run(EmbeddedServer, gatewayConfig, Environment.TEST)

        when:
        for (Class beanClazz : [
                GatewayRsaSignatureConfiguration,
                RSAKeyProvider,
                AuthenticationProviderUserPassword,
                GatewayBooksController,
                BooksClient,
                RSASignatureGeneratorConfiguration,
                SignatureConfiguration,
                SignatureGeneratorConfiguration
        ]) {
            gatewayEmbeddedServer.applicationContext.getBean(beanClazz)
        }

        then:
        noExceptionThrown()
    }

    @Ignore
    void "JWT generated with a RSASignatureGeneratorConfiguration can be verified in another service with a RSASignatureConfiguration "() {

        when:
        def configuration = new DefaultHttpClientConfiguration()
        configuration.setReadTimeout(Duration.ofSeconds(30))
        gatewayClient = gatewayEmbeddedServer.applicationContext.createBean(RxHttpClient, gatewayEmbeddedServer.getURL(), configuration)

        then:
        noExceptionThrown()

        when:
        String token = loginWith(client,'user', 'password')

        then:
        token
        !(JWTParser.parse(token) instanceof EncryptedJWT)
        JWTParser.parse(token) instanceof SignedJWT

        when:
        List<Book> books = gatewayClient.toBlocking().retrieve(HttpRequest.GET("/books").bearerAuth(token), Argument.of(List, Book))

        then:
        books
        books.size() == 1
    }

    @Override
    RxHttpClient getClient() {
        return gatewayClient
    }
}
