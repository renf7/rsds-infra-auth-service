package eu.rsdsoftware.auth.store;

import eu.rsdsoftware.auth.TransientRetention;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

/** Operator-invoked, one bounded page, dry-run by default; never invoked by the app. */
public final class RetentionBackfill {
    private RetentionBackfill() {}
    public static void main(String[] args) throws Exception {
        if(args.length<3 || args.length>4) throw new IllegalArgumentException("region table checkpoint-file [--apply]");
        boolean apply=args.length==4 && "--apply".equals(args[3]);
        if(args.length==4 && !apply) throw new IllegalArgumentException("Unknown mode");
        var checkpoint=java.nio.file.Path.of(args[2]);
        
        try(var client=DynamoDbClient.builder().region(Region.of(args[0])).build()) {
            run(client,args[1],checkpoint,apply);
        }
    }
    public static void run(DynamoDbClient client,String table,java.nio.file.Path checkpoint,boolean apply) throws Exception {
        String start=java.nio.file.Files.exists(checkpoint)?java.nio.file.Files.readString(checkpoint).strip():"";
            var request=ScanRequest.builder().tableName(table).limit(100).consistentRead(true)
                .projectionExpression("pk,revision,document,authDeleteAfter");
            if(!start.isEmpty()) request.exclusiveStartKey(Map.of("pk",AttributeValue.fromS(start)));
            var page=client.scan(request.build()); int eligible=0,changed=0,conflicts=0,skipped=0;
            for(var item:page.items()) {
                String key=item.get("pk").s();
                if(item.containsKey("authDeleteAfter") || !item.containsKey("document") || !item.containsKey("revision")) {skipped++;continue;}
                if(item.get("document").m().values().stream().anyMatch(value->value.s()==null)) {skipped++;continue;}
                Instant deadline;
                try {
                    var values=item.get("document").m().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey,e->e.getValue().s()));
                    deadline=TransientRetention.deadline(key,values,86400);
                } catch(IllegalArgumentException invalid) {skipped++;continue;}
                eligible++;
                // Old expired rows receive a full day for review/rollback; no immediate mass deletion.
                long deletion=Math.max(deadline.getEpochSecond(),Instant.now().plusSeconds(86400).getEpochSecond());
                if(apply) try {
                    client.updateItem(r->r.tableName(table).key(Map.of("pk",AttributeValue.fromS(key)))
                        .updateExpression("SET authDeleteAfter = :ttl")
                        .conditionExpression("revision = :revision AND attribute_not_exists(authDeleteAfter)")
                        .expressionAttributeValues(Map.of(":ttl",AttributeValue.fromN(Long.toString(deletion)),":revision",item.get("revision"))));
                    changed++;
                } catch(ConditionalCheckFailedException concurrentChange) {conflicts++;}
            }
            boolean more=!page.lastEvaluatedKey().isEmpty();
            // Cursor may contain a user key: persist privately, never emit keys/documents/tokens.
            if(apply && conflicts==0) {
                if(more) {
                    java.nio.file.Files.writeString(checkpoint,page.lastEvaluatedKey().get("pk").s());
                    if(java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"))
                        java.nio.file.Files.setPosixFilePermissions(checkpoint,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
                } else java.nio.file.Files.deleteIfExists(checkpoint);
            }
            System.out.printf(Locale.ROOT,"apply=%s scanned=%d eligible=%d changed=%d conflicts=%d skipped=%d more=%s%n",
                apply,page.scannedCount(),eligible,changed,conflicts,skipped,more);

    }
}
