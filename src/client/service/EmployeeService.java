package client.service;

import client.BootstrapClient;
import client.repository.MongoEmployeeRepository;
import crypto.EncryptionService;
import crypto.hom.OpeCipher;
import crypto.integrityandauthenticity.RecordSigner;
import crypto.integrityandauthenticity.RecordVerifier;
import org.bson.Document;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static client.service.RecordDecryptor.formatCentsAbs;

public final class EmployeeService {

    private final BootstrapClient bootstrapClient;
    private final MongoEmployeeRepository repository;
    private final EncryptionService encryptionService;
    private final RecordVerifier verifier;
    private final RecordDecryptor decryptor;
    private final RecordSigner recordSigner;
    private final OpeCipher salaryOpe;

    private boolean decryptResults = false;

    public EmployeeService(
            BootstrapClient bootstrapClient,
            MongoEmployeeRepository repository,
            EncryptionService encryptionService,
            RecordVerifier verifier,
            RecordDecryptor decryptor,
            RecordSigner recordSigner,
            OpeCipher salaryOpe
    ) {
        this.bootstrapClient = Objects.requireNonNull(bootstrapClient,"bootstrapClient");
        this.repository = Objects.requireNonNull(repository,"repository");
        this.encryptionService = Objects.requireNonNull(encryptionService,"encryptionService");
        this.verifier = Objects.requireNonNull(verifier,"verifier");
        this.decryptor = Objects.requireNonNull(decryptor,"decryptor");
        this.recordSigner = Objects.requireNonNull(recordSigner,"recordSigner");
        this.salaryOpe = Objects.requireNonNull(salaryOpe,"salaryOpe");
    }

    public boolean toggleDecryption() {
        decryptResults = !decryptResults;
        return decryptResults;
    }

    public boolean isDecryptionEnabled() {
        return decryptResults;
    }

    public int bootstrapFromCsv(Path csvPath) throws IOException {
        List<Map<String, Object>> records = bootstrapClient.bootstrap(csvPath);
        repository.deleteAll();
        repository.insertEncryptedRecords(records);
        return records.size();
    }

    public long countEmployees() {
        return repository.count();
    }

    public Map<String, Object> findByEmployeeId(String employeeId) {
        String encrypted = encryptionService.encryptEmployeeId(employeeId);
        return verifiedOne(repository.findOneByExactField("employeeID_det", encrypted));
    }

    public Map<String, Object> findByFullName(String fullName) {
        System.out.println(fullName);
        String encrypted = encryptionService.encryptFullName(fullName);
        return verifiedOne(repository.findOneByExactField("fullName_det", encrypted));
    }

    public List<Map<String, Object>> findByDepartment(String departmentId) {
        String encrypted = encryptionService.encryptDepartmentId(departmentId);
        return verifiedList(repository.findByExactField("department_det", encrypted));
    }

    public List<Map<String, Object>> orderedBySalary(boolean ascending) {
        return verifiedList(repository.findAllOrderedBy("salary_ope", ascending));
    }

    public List<Map<String, Object>> orderedByAge(boolean ascending) {
        return verifiedList(repository.findAllOrderedBy("age_ope", ascending));
    }

    public Map<String, Object> highestSalaryEmployee() {
        List<Map<String, Object>> ordered = orderedBySalary(false);
        return ordered.isEmpty() ? null : ordered.get(0);
    }

    public Map<String, Object> oldestEmployee() {
        List<Map<String, Object>> ordered = orderedByAge(false);
        return ordered.isEmpty() ? null : ordered.get(0);
    }

    public List<Map<String, Object>> findByDepartmentOrderedBySalary(
            String departmentId, boolean ascending) {
        String encryptedDept = encryptionService.encryptDepartmentId(departmentId);
        return verifiedList(
                repository.findByExactFieldAndOrderedBy(
                        "department_det", encryptedDept, "salary_ope", ascending));
    }

    public int compareSalaryByFullName(String fullNameA, String fullNameB) {
        String encA = encryptionService.encryptFullName(fullNameA);
        String encB = encryptionService.encryptFullName(fullNameB);

        Map<String, Object> a = verifiedOneRaw(
                repository.findOneByExactField("fullName_det", encA));
        Map<String, Object> b = verifiedOneRaw(
                repository.findOneByExactField("fullName_det", encB));

        if (a == null || b == null) {
            throw new IllegalArgumentException("One or both employees were not found.");
        }

        long salaryA = getLongField(a, "salary_ope");
        long salaryB = getLongField(b, "salary_ope");
        return Long.compare(salaryA, salaryB);
    }

    public long totalPayrollForDepartment(String departmentId) {
        String encrypted = encryptionService.encryptDepartmentId(departmentId);
        List<Map<String, Object>> employees =
                verifiedListForPayroll(repository.findByExactField("department_det", encrypted));

        BigInteger totalCipher = null;

        for (Map<String, Object> employee : employees) {
            String salaryHom = getStringField(employee, "salary_hom");
            if (salaryHom == null || salaryHom.isBlank()) {
                continue;
            }
            BigInteger cipher = new BigInteger(salaryHom);
            totalCipher = (totalCipher == null)
                    ? cipher
                    : encryptionService.addEncryptedSalary(totalCipher, cipher);
        }

        return totalCipher == null ? 0L : encryptionService.decryptSalaryCents(totalCipher);
    }

    public long bonusForEmployee(String fullName) {
        String encrypted = encryptionService.encryptFullName(fullName);
        Map<String, Object> employee = verifiedOneRaw(
                repository.findOneByExactField("fullName_det", encrypted));

        if (employee == null) {
            throw new IllegalArgumentException("Employee not found: " + fullName);
        }

        String salaryHom = getStringField(employee, "salary_hom");
        if (salaryHom == null || salaryHom.isBlank()) {
            return 0L;
        }

        BigInteger salaryCipher = new BigInteger(salaryHom);
        BigInteger bonusCipher  = encryptionService.multiplyEncryptedSalary(salaryCipher, 25L);
        long bonusCentsScaled   = encryptionService.decryptSalaryCents(bonusCipher);
        return bonusCentsScaled / 100L;
    }

    public long applyBonusForEmployee(String fullName) {
        String encrypted = encryptionService.encryptFullName(fullName);
        Map<String, Object> employee = verifiedOneRaw(
                repository.findOneByExactField("fullName_det", encrypted));

        if (employee == null) {
            throw new IllegalArgumentException("Employee not found: " + fullName);
        }

        String salaryHomStr = getStringField(employee, "salary_hom");
        if (salaryHomStr == null || salaryHomStr.isBlank()) {
            return 0L;
        }

        BigInteger currentCipher  = new BigInteger(salaryHomStr);
        long       currentCents   = encryptionService.decryptSalaryCents(currentCipher);

        long bonusCents     = currentCents * 25L / 100L;
        long newSalaryCents = currentCents + bonusCents;

        BigInteger newSalaryHom = encryptionService.encryptSalaryCents(newSalaryCents);

        long newSalaryOpe = salaryOpe.encrypt(newSalaryCents);

        Map<String, Object> updatedRecord = new LinkedHashMap<>(employee);
        updatedRecord.put("salary_hom", newSalaryHom.toString());
        updatedRecord.put("salary_ope", newSalaryOpe);

        Map<String, Object> resigned = recordSigner.resign(updatedRecord);

        Map<String, Object> fieldsToUpdate = new LinkedHashMap<>();
        fieldsToUpdate.put("salary_hom",        resigned.get("salary_hom"));
        fieldsToUpdate.put("salary_ope",         resigned.get("salary_ope"));
        fieldsToUpdate.put("record_hmac",        resigned.get("record_hmac"));
        fieldsToUpdate.put("record_signature",   resigned.get("record_signature"));

        repository.updateFields(employee.get("_id"), fieldsToUpdate);

        return bonusCents;
    }

    public List<Map<String, Object>> bonusesForEligibleEmployees() {
        List<Map<String, Object>> eligible = findByBonusEligibilityRaw(true);
        List<Map<String, Object>> result   = new ArrayList<>(eligible.size());

        for (Map<String, Object> employee : eligible) {
            String salaryHom  = getStringField(employee, "salary_hom");
            long   bonusCents = 0L;

            if (salaryHom != null && !salaryHom.isBlank()) {
                BigInteger salaryCipher = new BigInteger(salaryHom);
                BigInteger bonusCipher  = encryptionService.multiplyEncryptedSalary(salaryCipher, 25L);
                bonusCents = encryptionService.decryptSalaryCents(bonusCipher) / 100L;
            }

            Map<String, Object> display = displayRecord(employee);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("employeeID", displayString(display, "employeeID", "employeeID_det"));
            row.put("fullName", displayString(display, "fullName", "fullName_det"));
            row.put("bonus_cents", bonusCents);
            row.put("bonus", formatCentsAbs(bonusCents));

            result.add(row);
        }

        return result;
    }

    public List<Map<String, Object>> applyBonusesToEligibleEmployees() {
        List<Map<String, Object>> eligible = findByBonusEligibilityRaw(true);
        List<Map<String, Object>> result   = new ArrayList<>(eligible.size());

        for (Map<String, Object> employee : eligible) {
            String salaryHomStr = getStringField(employee, "salary_hom");
            long bonusCents = 0L;

            if (salaryHomStr != null && !salaryHomStr.isBlank()) {
                BigInteger currentCipher = new BigInteger(salaryHomStr);
                long currentCents = encryptionService.decryptSalaryCents(currentCipher);
                bonusCents = currentCents * 25L / 100L;
                long newSalaryCents = currentCents + bonusCents;

                BigInteger newSalaryHom = encryptionService.encryptSalaryCents(newSalaryCents);
                long newSalaryOpe = salaryOpe.encrypt(newSalaryCents);

                Map<String, Object> updatedRecord = new LinkedHashMap<>(employee);
                updatedRecord.put("salary_hom", newSalaryHom.toString());
                updatedRecord.put("salary_ope", newSalaryOpe);

                Map<String, Object> resigned = recordSigner.resign(updatedRecord);

                Map<String, Object> fieldsToUpdate = new LinkedHashMap<>();
                fieldsToUpdate.put("salary_hom", resigned.get("salary_hom"));
                fieldsToUpdate.put("salary_ope", resigned.get("salary_ope"));
                fieldsToUpdate.put("record_hmac", resigned.get("record_hmac"));
                fieldsToUpdate.put("record_signature", resigned.get("record_signature"));

                repository.updateFields(employee.get("_id"), fieldsToUpdate);
            }

            Map<String, Object> display = displayRecord(employee);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("employeeID", displayString(display, "employeeID", "employeeID_det"));
            row.put("fullName", displayString(display, "fullName", "fullName_det"));
            row.put("bonus_cents", bonusCents);
            row.put("bonus", formatCentsAbs(bonusCents));

            result.add(row);
        }

        return result;
    }

    private List<Map<String, Object>> findByBonusEligibilityRaw(boolean eligible) {
        String value     = eligible ? "yes" : "no";
        String encrypted = encryptionService.encryptDeterministic(value);
        List<Map<String, Object>> raw =
                repository.findByExactField("bonusEligibility_det", encrypted);
        for (Map<String, Object> record : raw) {
            verifier.verifyOrThrow(record);
        }
        return raw;
    }

    private Map<String, Object> verifiedOne(Map<String, Object> record) {
        if (record == null) return null;
        verifier.verifyOrThrow(record);
        return decryptResults ? decryptor.decrypt(record) : record;
    }

    private Map<String, Object> verifiedOneRaw(Map<String, Object> record) {
        if (record == null) return null;
        verifier.verifyOrThrow(record);
        return record;
    }

    public Path snapshotEncryptedDatabase(Path outputFile) throws IOException {
        List<Document> docs = repository.findAllDocuments();

        Path parent = outputFile.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(
                outputFile,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        )) {
            for (Document doc : docs) {
                writer.write(doc.toJson());
                writer.newLine();
            }
        }

        return outputFile;
    }

    private List<Map<String, Object>> verifiedList(List<Map<String, Object>> records) {
        List<Map<String, Object>> result = new ArrayList<>(records.size());
        for (Map<String, Object> record : records) {
            verifier.verifyOrThrow(record);
            result.add(decryptResults ? decryptor.decrypt(record) : record);
        }
        return result;
    }

    private List<Map<String, Object>> verifiedListForPayroll(List<Map<String, Object>> records) {
        List<Map<String, Object>> result = new ArrayList<>(records.size());
        for (Map<String, Object> record : records) {
            verifier.verifyOrThrow(record);
            result.add(record);
        }
        return result;
    }

    private static long getLongField(Map<String, Object> record, String field) {
        Object value = record.get(field);
        if (value == null) {
            throw new IllegalStateException("Missing field: " + field);
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }

    private static String getStringField(Map<String, Object> record, String field) {
        Object value = record.get(field);
        return value == null ? null : String.valueOf(value);
    }

    private Map<String, Object> displayRecord(Map<String, Object> employee) {
        return decryptResults ? decryptor.decrypt(employee) : employee;
    }

    private static String displayString(Map<String, Object> record, String plainKey, String encryptedKey) {
        Object value = record.get(plainKey);
        if (value == null) value = record.get(encryptedKey);
        return value == null ? "" : String.valueOf(value);
    }
}