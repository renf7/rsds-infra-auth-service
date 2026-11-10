package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import java.net.URI;
@EnabledIfEnvironmentVariable(named="TEST_DYNAMO_ENDPOINT",matches="http://.+")
class DynamoDocumentStoreTest extends DocumentStoreContract {
    @org.junit.jupiter.api.Test void accountUniquenessAndBindingsWorkAgainstActualDynamoDb() {
        var identities=new IdentityService(store()); String suffix=java.util.UUID.randomUUID().toString();
        var first=identities.login("google","issuer",suffix,"Alice",suffix+"@example.test",true);
        var next=identities.login("github","github",suffix,"Alice",suffix+"@example.test",true);
        org.junit.jupiter.api.Assertions.assertNotEquals(first.subject(),next.subject());
        org.junit.jupiter.api.Assertions.assertEquals(first,identities.find(first.subject()).orElseThrow());
    }
    @Override DocumentStore store() {
        var client=DynamoDbClient.builder().endpointOverride(URI.create(System.getenv("TEST_DYNAMO_ENDPOINT"))).region(Region.EU_CENTRAL_1)
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("local","local"))).build();
        return new DynamoDocumentStore(client,"auth-contract",true);
    }
}

