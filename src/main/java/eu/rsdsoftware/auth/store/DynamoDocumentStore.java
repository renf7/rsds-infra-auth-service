package eu.rsdsoftware.auth.store;
import java.util.*;
import java.util.stream.Collectors;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

public final class DynamoDocumentStore implements DocumentStore {
    private final DynamoDbClient client;
    private final String table;
    @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="EI_EXPOSE_REP2",justification="AWS SDK client is a thread-safe shared injected resource, closed by Spring; copying is not supported. No reference is exposed.")
    public DynamoDocumentStore(DynamoDbClient client, String table, boolean provisionLocal) {
        this.client = client; this.table = table;
        if (provisionLocal) {
            try {
                client.createTable(r -> r.tableName(table).billingMode(BillingMode.PAY_PER_REQUEST)
                    .keySchema(KeySchemaElement.builder().attributeName("pk").keyType(KeyType.HASH).build())
                    .attributeDefinitions(AttributeDefinition.builder().attributeName("pk").attributeType(ScalarAttributeType.S).build()));
            } catch (ResourceInUseException ignored) { /* Existing local table is retained. */ }
            client.waiter().waitUntilTableExists(r -> r.tableName(table));
        }
    }
    private Map<String,AttributeValue> key(String key) { return Map.of("pk", AttributeValue.fromS(key)); }
    @Override public Optional<Snapshot> get(String key) {
        var item = client.getItem(r -> r.tableName(table).key(key(key)).consistentRead(true)).item();
        if (item.isEmpty()) return Optional.empty();
        var values = item.get("document").m().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,e -> e.getValue().s()));
        var expiry=item.get("authDeleteAfter");
        return Optional.of(new Snapshot(item.get("revision").s(),values,expiry==null?null:java.time.Instant.ofEpochSecond(Long.parseLong(expiry.n()))));
    }
    @Override public boolean insert(String key, Map<String,String> values) { return write(key,null,values,null); }
    @Override public boolean replace(String key, String expectedRevision, Map<String,String> values) {
        Objects.requireNonNull(expectedRevision);
        return write(key,expectedRevision,values,get(key).map(Snapshot::deleteAfter).orElse(null));
    }
    @Override public boolean insertExpiring(String key, Map<String,String> values, java.time.Instant deleteAfter) {
        return write(key,null,values,Objects.requireNonNull(deleteAfter));
    }
    @Override public boolean replaceExpiring(String key,String revision,Map<String,String> values,java.time.Instant deleteAfter) {
        return write(key,Objects.requireNonNull(revision),values,Objects.requireNonNull(deleteAfter));
    }
    private boolean write(String key, String revision, Map<String,String> values,java.time.Instant deleteAfter) {
        var fields = values.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,e -> AttributeValue.fromS(e.getValue())));
        var item = new HashMap<>(Map.of("pk",AttributeValue.fromS(key),"revision",AttributeValue.fromS(UUID.randomUUID().toString()),"document",AttributeValue.fromM(fields)));
        if(deleteAfter!=null) {
            // Shared table safety: never attach native TTL to an identity or another service.
            eu.rsdsoftware.auth.TransientRetention.deadline(key,values,86400);
            item.put("authDeleteAfter",AttributeValue.fromN(Long.toString(deleteAfter.getEpochSecond())));
        }
        var request = PutItemRequest.builder().tableName(table).item(item);
        if (revision == null) request.conditionExpression("attribute_not_exists(pk)");
        else request.conditionExpression("revision = :expected").expressionAttributeValues(Map.of(":expected",AttributeValue.fromS(revision)));
        try { client.putItem(request.build()); return true; }
        catch (ConditionalCheckFailedException ignored) { return false; }
    }
}

