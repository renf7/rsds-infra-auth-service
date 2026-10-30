package eu.rsdsoftware.auth;
import eu.rsdsoftware.auth.store.DocumentStore;
class InMemoryDocumentStoreTest extends DocumentStoreContract {
    @Override DocumentStore store() { return new InMemoryDocumentStore(); }
}

