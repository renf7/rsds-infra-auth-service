package eu.rsdsoftware.auth;

import eu.rsdsoftware.auth.store.RetentionBackfill;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class RetentionBackfillTest {
    @TempDir Path directory;
    private Map<String,AttributeValue> row(String key,Map<String,AttributeValue> values) {
        return Map.of("pk",AttributeValue.fromS(key),"revision",AttributeValue.fromS("old"),"document",AttributeValue.fromM(values));
    }
    @Test void boundedPaginationPreservesDryRunCursorAndAdvancesOnlyAfterApply() throws Exception {
        var client=mock(DynamoDbClient.class);Path cursor=directory.resolve("cursor");Files.writeString(cursor,"previous");
        var valid=row("auth:v2:mail-rate:hash",Map.of("after",AttributeValue.fromS("123")));
        var invalid=row("auth:v1:refresh:hash",Map.of("expires",AttributeValue.fromS("bad")));
        var numeric=row("auth:v1:refresh:hash",Map.of("expires",AttributeValue.fromN("123")));
        var missing=Map.of("pk",AttributeValue.fromS("missing"));
        var existing=new HashMap<>(valid);existing.put("authDeleteAfter",AttributeValue.fromN("999"));
        when(client.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().items(List.of(valid,invalid,numeric,missing,existing))
            .scannedCount(5).lastEvaluatedKey(Map.of("pk",AttributeValue.fromS("next"))).build());
        RetentionBackfill.run(client,"test",cursor,false);
        assertEquals("previous",Files.readString(cursor));
        verify(client,never()).updateItem(org.mockito.ArgumentMatchers.<Consumer<UpdateItemRequest.Builder>>any());
        RetentionBackfill.run(client,"test",cursor,true);
        assertEquals("next",Files.readString(cursor));
        var requests=org.mockito.ArgumentCaptor.forClass(ScanRequest.class);verify(client,times(2)).scan(requests.capture());
        assertEquals(100,requests.getValue().limit());assertTrue(requests.getValue().consistentRead());
        assertEquals("previous",requests.getAllValues().getFirst().exclusiveStartKey().get("pk").s());
        assertThrows(IllegalArgumentException.class,()->RetentionBackfill.run(client,"test",cursor,true,1));
    }
    @Test void concurrentChangePreventsCursorAdvanceAndRetryIsSafe() throws Exception {
        var client=mock(DynamoDbClient.class);Path cursor=directory.resolve("cursor");Files.writeString(cursor,"previous");
        when(client.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder()
            .items(row("auth:v1:refresh:hash",Map.of("expires",AttributeValue.fromS("123"))))
            .scannedCount(1).lastEvaluatedKey(Map.of("pk",AttributeValue.fromS("next"))).build());
        when(client.updateItem(org.mockito.ArgumentMatchers.<Consumer<UpdateItemRequest.Builder>>any()))
            .thenThrow(ConditionalCheckFailedException.builder().message("conflict").build());
        RetentionBackfill.run(client,"test",cursor,true);
        assertEquals("previous",Files.readString(cursor));
    }
    @Test void invalidCliArgumentsCannotReachAws() {
        assertThrows(IllegalArgumentException.class,()->RetentionBackfill.main(new String[]{}));
        assertThrows(IllegalArgumentException.class,()->RetentionBackfill.main(new String[]{"region","table","cursor","--unknown"}));
    }
    @Test void cliDefaultsToDryRunAndRequiresExplicitApply() throws Exception {
        var client=mock(DynamoDbClient.class);
        var builder=mock(software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder.class);
        when(builder.region(any(software.amazon.awssdk.regions.Region.class))).thenReturn(builder);
        when(builder.build()).thenReturn(client);
        when(client.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().scannedCount(0).build());
        try(var factory=mockStatic(DynamoDbClient.class)) {
            factory.when(DynamoDbClient::builder).thenReturn(builder);
            String[] args={"eu-central-1","test",directory.resolve("cursor").toString()};
            RetentionBackfill.main(args);
            RetentionBackfill.main(new String[]{args[0],args[1],args[2],"--apply"});
            verify(client,times(2)).scan(any(ScanRequest.class));
            verify(client,times(2)).close();
        }
    }
}
