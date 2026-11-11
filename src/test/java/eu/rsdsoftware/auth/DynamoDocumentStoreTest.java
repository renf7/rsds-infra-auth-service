package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import java.net.URI;
@EnabledIfEnvironmentVariable(named="TEST_DYNAMO_ENDPOINT",matches="http://.+")
class DynamoDocumentStoreTest extends DocumentStoreContract {
    @org.junit.jupiter.api.Test void nativeNumericTtlAndBoundedBackfillExcludePermanentRows(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory) throws Exception {
        try(var client=DynamoDbClient.builder().endpointOverride(URI.create(System.getenv("TEST_DYNAMO_ENDPOINT"))).region(Region.EU_CENTRAL_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("local","local"))).build()) {
            String table="retention-"+java.util.UUID.randomUUID();
            var store=new DynamoDocumentStore(client,table,true);
            String transientKey="auth:v1:refresh:"+java.util.UUID.randomUUID();
            String permanent="auth:v2:account:"+java.util.UUID.randomUUID();
            store.insert(transientKey,java.util.Map.of("expires","123"));
            store.insert(permanent,java.util.Map.of("expires","123"));
            store.insert("offers:another-service",java.util.Map.of("expires","123"));
            var checkpoint=directory.resolve("cursor");
            RetentionBackfill.run(client,table,checkpoint,false);
            org.junit.jupiter.api.Assertions.assertNull(store.get(transientKey).orElseThrow().deleteAfter());
            RetentionBackfill.run(client,table,checkpoint,true);
            var raw=client.getItem(r->r.tableName(table).key(java.util.Map.of("pk",software.amazon.awssdk.services.dynamodb.model.AttributeValue.fromS(transientKey))).consistentRead(true)).item();
            org.junit.jupiter.api.Assertions.assertNotNull(raw.get("authDeleteAfter").n());
            org.junit.jupiter.api.Assertions.assertNull(raw.get("authDeleteAfter").s());
            org.junit.jupiter.api.Assertions.assertTrue(store.get(transientKey).orElseThrow().deleteAfter().isAfter(java.time.Instant.now()));
            org.junit.jupiter.api.Assertions.assertNull(store.get(permanent).orElseThrow().deleteAfter());
            org.junit.jupiter.api.Assertions.assertNull(store.get("offers:another-service").orElseThrow().deleteAfter());
            RetentionBackfill.run(client,table,checkpoint,true); // Existing metadata is not rewritten.
        }
    }
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

