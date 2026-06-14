package client.repository;

import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.mongodb.client.model.Filters.eq;
import static com.mongodb.client.model.Sorts.ascending;
import static com.mongodb.client.model.Sorts.descending;

public final class MongoEmployeeRepository implements AutoCloseable {

    private final MongoClient mongoClient;
    private final MongoCollection<Document> collection;

    public MongoEmployeeRepository(String mongoUri, String databaseName, String collectionName) {
        Objects.requireNonNull(mongoUri, "mongoUri");
        Objects.requireNonNull(databaseName, "databaseName");
        Objects.requireNonNull(collectionName, "collectionName");

        this.mongoClient = MongoClients.create(mongoUri);
        MongoDatabase database = mongoClient.getDatabase(databaseName);
        this.collection = database.getCollection(collectionName);
    }

    public void insertEncryptedRecord(Map<String, Object> record) {
        Objects.requireNonNull(record, "record");
        collection.insertOne(toDocument(record));
    }

    public void insertEncryptedRecords(List<Map<String, Object>> records) {
        Objects.requireNonNull(records, "records");

        List<Document> docs = new ArrayList<>(records.size());
        for (Map<String, Object> record : records) {
            docs.add(toDocument(record));
        }

        if (!docs.isEmpty()) {
            collection.insertMany(docs);
        }
    }

    public void updateFields(Object documentId, Map<String, Object> fieldsToUpdate) {
        Objects.requireNonNull(documentId,    "documentId");
        Objects.requireNonNull(fieldsToUpdate, "fieldsToUpdate");
        if (fieldsToUpdate.isEmpty()) {
            return;
        }
        Document setDoc = toDocument(fieldsToUpdate);
        collection.updateOne(eq("_id", documentId), new Document("$set", setDoc));
    }

    public Map<String, Object> findOneByExactField(String fieldName, Object encryptedValue) {
        Document doc = collection.find(eq(fieldName, encryptedValue)).first();
        return doc == null ? null : toMap(doc);
    }

    public List<Map<String, Object>> findByExactField(String fieldName, Object encryptedValue) {
        return toMapList(collection.find(eq(fieldName, encryptedValue)));
    }

    public List<Map<String, Object>> findAllOrderedBy(String fieldName, boolean ascendingOrder) {
        FindIterable<Document> docs = collection.find()
                .sort(ascendingOrder ? ascending(fieldName) : descending(fieldName));
        return toMapList(docs);
    }

    public List<Map<String, Object>> findByExactFieldAndOrderedBy(
            String filterField,
            Object filterValue,
            String orderField,
            boolean ascendingOrder
    ) {
        FindIterable<Document> docs = collection.find(eq(filterField, filterValue))
                .sort(ascendingOrder ? ascending(orderField) : descending(orderField));
        return toMapList(docs);
    }

    public long count() {
        return collection.countDocuments();
    }

    public void deleteAll() {
        collection.deleteMany(new Document());
    }

    public List<Document> findAllDocuments() {
        List<Document> result = new ArrayList<>();
        for (Document doc : collection.find()) {
            result.add(new Document(doc));
        }
        return result;
    }

    @Override
    public void close() {
        mongoClient.close();
    }

    private static List<Map<String, Object>> toMapList(FindIterable<Document> docs) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Document doc : docs) {
            result.add(toMap(doc));
        }
        return result;
    }

    private static Map<String, Object> toMap(Document doc) {
        return new LinkedHashMap<>(doc);
    }

    private static Document toDocument(Map<String, Object> record) {
        Document doc = new Document();
        for (Map.Entry<String, Object> entry : record.entrySet()) {
            doc.put(entry.getKey(), entry.getValue());
        }
        return doc;
    }
}