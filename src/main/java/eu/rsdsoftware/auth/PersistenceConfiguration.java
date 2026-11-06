package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.*;
import java.net.URI;
import org.springframework.context.annotation.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@Configuration
public class PersistenceConfiguration {
    @Bean(destroyMethod="close") DynamoDbClient dynamo(AuthSettings settings) {
        var builder=DynamoDbClient.builder().region(Region.of(settings.region()));
        if(settings.local()) builder.endpointOverride(URI.create(settings.dynamoEndpoint()))
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("local","local")));
        // Production uses the SDK default credential chain, e.g. workload identity; no embedded cloud credentials.
        return builder.build();
    }
    @Bean DocumentStore documents(DynamoDbClient client,AuthSettings settings) {
        return new DynamoDocumentStore(client,settings.table(),settings.local());
    }
}

