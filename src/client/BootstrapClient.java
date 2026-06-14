package client;

import client.config.ClientEmployeeIndexStore;
import crypto.EncryptionService;
import crypto.integrityandauthenticity.HmacUtil;
import crypto.hom.OpeCipher;
import crypto.integrityandauthenticity.SignatureUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

public final class BootstrapClient {

    private final EncryptionService encryptionService;
    private final OpeCipher         ageOpe;
    private final OpeCipher         salaryOpe;
    private final PrivateKey        signingPrivateKey;
    private final byte[]            hmacKey;
    private final ClientEmployeeIndexStore employeeIndexStore;

    public BootstrapClient(
            EncryptionService encryptionService,
            OpeCipher         ageOpe,
            OpeCipher         salaryOpe,
            PrivateKey        signingPrivateKey,
            byte[]            hmacKey,
            ClientEmployeeIndexStore employeeIndexStore
    ) {
        this.encryptionService = Objects.requireNonNull(encryptionService,"encryptionService");
        this.ageOpe = Objects.requireNonNull(ageOpe,"ageOpe");
        this.salaryOpe = Objects.requireNonNull(salaryOpe,"salaryOpe");
        this.signingPrivateKey = Objects.requireNonNull(signingPrivateKey,"signingPrivateKey");
        this.hmacKey = Objects.requireNonNull(hmacKey,"hmacKey").clone();
        this.employeeIndexStore = Objects.requireNonNull(employeeIndexStore,"employeeIndexStore");
    }

    public List<Map<String, Object>> bootstrap(Path csvPath) throws IOException {
        List<Map<String, String>> rows = readCsv(csvPath);
        if (rows.isEmpty()) {
            return Collections.emptyList();
        }

        employeeIndexStore.clear();

        TreeSet<Long> ages = new TreeSet<>();
        TreeSet<Long> salaries = new TreeSet<>();

        List<RowEnvelope> envelopes = new ArrayList<>(rows.size());
        for (Map<String, String> row : rows) {
            long age = parseAge(
                    firstNonBlank(row, "Age", "age"),
                    firstNonBlank(row, "DateOfBirth", "dateOfBirth", "DOB", "dob"));
            long salaryCents = parseMoneyToCents(
                    firstNonBlank(row, "salary", "Salary", "BaseSalary", "baseSalary"));

            if (age >= 0)         ages.add(age);
            if (salaryCents >= 0) salaries.add(salaryCents);

            envelopes.add(new RowEnvelope(row, age, salaryCents));
        }

        Map<Long, Long> ageCipherByPlain = buildOpeMap(ages, ageOpe);
        Map<Long, Long> salaryCipherByPlain = buildOpeMap(salaries, salaryOpe);

        List<Map<String, Object>> encryptedRecords = new ArrayList<>(envelopes.size());
        long sourceRow = 0;

        for (RowEnvelope envelope : envelopes) {
            encryptedRecords.add(bootstrapRow(
                    envelope.row,
                    envelope.age,
                    envelope.salaryCents,
                    ageCipherByPlain,
                    salaryCipherByPlain,
                    sourceRow++
            ));
        }

        employeeIndexStore.save();
        return encryptedRecords;
    }

    public Map<String, Object> bootstrapRow(
            Map<String, String> row,
            long age,
            long salaryCents,
            Map<Long, Long> ageCipherByPlain,
            Map<Long, Long> salaryCipherByPlain,
            long sourceRow
    ) throws IOException {
        Map<String, Object> record = new LinkedHashMap<>();

        String employeeId = firstNonBlank(row, "employeeID", "EmployeeID", "employeeId", "id", "ID");
        String firstName = firstNonBlank(row, "FirstName", "firstName");
        String lastName = firstNonBlank(row, "LastName", "lastName");
        String fullName = firstNonBlank(row, "FullName", "fullName");
        String dateOfBirth = firstNonBlank(row, "DateOfBirth","dateOfBirth","DOB", "dob");
        String email = firstNonBlank(row, "Email", "email");
        String phone = firstNonBlank(row, "Phone", "phone", "PhoneNumber", "phoneNumber");
        String jobTitle = firstNonBlank(row, "JobTitle", "jobTitle", "Title", "title");
        String departmentId = firstNonBlank(row, "DepartmentID", "DepartmentId", "departmentID", "departmentId", "Department", "department");
        String hireDate = firstNonBlank(row, "HireDate", "hireDate");
        String employmentType = firstNonBlank(row, "EmploymentType", "employmentType");
        String salaryBand = firstNonBlank(row, "SalaryBand", "salaryBand");
        String bonusElig = firstNonBlank(row, "BonusEligibility", "bonusEligibility", "Bonus Eligible", "bonusEligible");

        String encryptedEmployeeId = encryptionService.encryptEmployeeId(employeeId);
        record.put("employeeID_det", encryptedEmployeeId);
        record.put("employeeID_hash", encryptionService.hashIndex(employeeId));

        String displayFullName = resolveFullName(fullName, firstName, lastName);
        record.put("fullName_det", encryptionService.encryptFullName(fullName));
        record.put("fullName_hash", encryptionService.hashIndex(fullName));

        record.put("department_det", encryptionService.encryptDepartmentId(departmentId));
        record.put("department_hash", encryptionService.hashIndex(departmentId));

        record.put("bonusEligibility_det", encryptionService.encryptDeterministic(normalizeBooleanLike(bonusElig)));
        record.put("bonusEligibility_hash", encryptionService.hashIndex(normalizeBooleanLike(bonusElig)));

        record.put("firstName_rnd", encryptionService.encryptSensitiveText(firstName));
        record.put("lastName_rnd", encryptionService.encryptSensitiveText(lastName));
        record.put("dateOfBirth_rnd", encryptionService.encryptSensitiveText(dateOfBirth));
        record.put("email_rnd", encryptionService.encryptSensitiveText(email));
        record.put("phone_rnd", encryptionService.encryptSensitiveText(phone));
        record.put("jobTitle_rnd", encryptionService.encryptSensitiveText(jobTitle));
        record.put("hireDate_rnd", encryptionService.encryptSensitiveText(hireDate));
        record.put("employmentType_rnd", encryptionService.encryptSensitiveText(employmentType));
        record.put("salaryBand_rnd", encryptionService.encryptSensitiveText(salaryBand));

        record.put("age_ope", age >= 0 ? ageCipherByPlain.get(age) : null);

        if (salaryCents >= 0) {
            record.put("salary_ope", salaryCipherByPlain.get(salaryCents));
            BigInteger salaryHom = encryptionService.encryptSalaryCents(salaryCents);
            record.put("salary_hom", salaryHom.toString());
        } else {
            record.put("salary_ope", null);
            record.put("salary_hom", null);
        }

        record.put("schema_version", "1");
        record.put("source_row", sourceRow);

        String payload = canonicalPayload(record);
        byte[] hmac = HmacUtil.hmacSha256(hmacKey, payload);
        String hmacB64 = Base64.getEncoder().encodeToString(hmac);
        record.put("record_hmac", hmacB64);

        byte[] signature = SignatureUtil.sign(signingPrivateKey, payload + "|hmac=" + hmacB64);
        record.put("record_signature", Base64.getEncoder().encodeToString(signature));

        employeeIndexStore.put(encryptedEmployeeId, employeeId, displayFullName);

        return record;
    }

    public void saveEmployeeIndex() throws IOException {
        employeeIndexStore.save();
    }

    private static String resolveFullName(String fullName, String firstName, String lastName) {
        if (fullName != null && !fullName.isBlank()) {
            return fullName.trim();
        }
        String combined = (firstName + " " + lastName).trim();
        return combined.isBlank() ? "" : combined;
    }

    private static Map<Long, Long> buildOpeMap(TreeSet<Long> sortedValues, OpeCipher ope) {
        Map<Long, Long> map = new LinkedHashMap<>();
        for (Long value : sortedValues) {
            map.put(value, ope.encrypt(value));
        }
        return map;
    }

    private static List<Map<String, String>> readCsv(Path csvPath) throws IOException {
        Map<String, String> headerAliases = Map.ofEntries(
                Map.entry("employeeid", "employeeID"),
                Map.entry("first name", "FirstName"),
                Map.entry("firstname", "FirstName"),
                Map.entry("last name", "LastName"),
                Map.entry("lastname", "LastName"),
                Map.entry("full name", "FullName"),
                Map.entry("fullname", "FullName"),
                Map.entry("dateofbirth", "DateOfBirth"),
                Map.entry("date of birth", "DateOfBirth"),
                Map.entry("dob", "DateOfBirth"),
                Map.entry("email", "Email"),
                Map.entry("contact phone number", "Phone"),
                Map.entry("personal phone number", "Phone"),
                Map.entry("jobtitle", "JobTitle"),
                Map.entry("departmentid", "DepartmentID"),
                Map.entry("hiredate", "HireDate"),
                Map.entry("emploiementtype", "EmploymentType"), // CSV typo
                Map.entry("employmenttype", "EmploymentType"),
                Map.entry("salary", "Salary"),
                Map.entry("salaryband", "SalaryBand"),
                Map.entry("bonuseligibiity", "BonusEligibility"), // CSV typo
                Map.entry("bonus eligibility", "BonusEligibility"),
                Map.entry("bonuseligible", "BonusEligibility")
        );

        try (BufferedReader reader = Files.newBufferedReader(csvPath, StandardCharsets.UTF_8)) {
            String headerLine = nextNonEmptyLine(reader);
            if (headerLine == null) {
                return Collections.emptyList();
            }

            List<String> rawHeaders = parseCsvLine(headerLine);
            List<String> normalizedHeaders = new ArrayList<>();

            for (String h : rawHeaders) {
                String key = h.trim().toLowerCase(Locale.ROOT);
                key = headerAliases.getOrDefault(key, h.trim());
                normalizedHeaders.add(key);
            }

            List<Map<String, String>> rows = new ArrayList<>();
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;

                List<String> values = parseCsvLine(line);
                Map<String, String> row = new LinkedHashMap<>();

                int limit = Math.min(normalizedHeaders.size(), values.size());
                for (int i = 0; i < limit; i++) {
                    row.put(normalizedHeaders.get(i), values.get(i).trim());
                }

                rows.add(row);
            }

            return rows;
        }
    }


    private static String nextNonEmptyLine(BufferedReader reader) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.trim().isEmpty()) return line;
        }
        return null;
    }

    private static Map<String, String> zipRow(List<String> headers, List<String> values) {
        Map<String, String> row = new LinkedHashMap<>();
        int limit = Math.min(headers.size(), values.size());
        for (int i = 0; i < limit; i++) {
            row.put(headers.get(i).trim(), values.get(i).trim());
        }
        return row;
    }

    private static List<String> parseCsvLine(String line) {
        List<String> result  = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        result.add(current.toString());
        return result;
    }

    private static String firstNonBlank(Map<String, String> row, String... keys) {
        for (String key : keys) {
            String value = row.get(key);
            if (value != null && !value.trim().isEmpty()) return value.trim();
        }
        return "";
    }

    private static String normalizeBooleanLike(String value) {
        String v = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("y") || v.equals("eligible")) {
            return "yes";
        }
        if (v.equals("0") || v.equals("false") || v.equals("no") || v.equals("n") || v.equals("not eligible")) {
            return "no";
        }
        return v;
    }

    private static long parseAge(String ageText, String dateOfBirthText) {
        Long age = tryParseLong(ageText);
        if (age != null && age >= 0) return age;

        if (dateOfBirthText == null || dateOfBirthText.isBlank()) return -1;

        List<DateTimeFormatter> formatters = List.of(
                DateTimeFormatter.ISO_LOCAL_DATE,
                DateTimeFormatter.ofPattern("dd/MM/yyyy"),
                DateTimeFormatter.ofPattern("MM/dd/yyyy")
        );

        for (DateTimeFormatter formatter : formatters) {
            try {
                LocalDate dob = LocalDate.parse(dateOfBirthText.trim(), formatter);
                return ChronoUnit.YEARS.between(dob, LocalDate.now());
            } catch (Exception ignored) {}
        }
        return -1;
    }

    private static long parseMoneyToCents(String salaryText) {
        if (salaryText == null || salaryText.trim().isEmpty()) return -1;

        String cleaned = salaryText.trim()
                .replace("€", "").replace("$", "").replace("£", "").replace(" ", "");

        if (cleaned.contains(",") && cleaned.contains(".")) {
            cleaned = cleaned.replace(",", "");
        } else if (cleaned.contains(",") && !cleaned.contains(".")) {
            cleaned = cleaned.replace(",", ".");
        }

        try {
            BigDecimal amount = new BigDecimal(cleaned);
            return amount.movePointRight(2).setScale(0, RoundingMode.HALF_UP).longValueExact();
        } catch (Exception e) {
            return -1;
        }
    }

    private static Long tryParseLong(String text) {
        if (text == null || text.isBlank()) return null;
        try {
            return Long.parseLong(text.trim());
        } catch (Exception e) {
            return null;
        }
    }

    private static String canonicalPayload(Map<String, Object> record) {
        List<String> keys = new ArrayList<>(record.keySet());
        Collections.sort(keys);

        StringBuilder sb = new StringBuilder();
        for (String key : keys) {
            if (key.equals("record_hmac") || key.equals("record_signature")) continue;
            sb.append(key).append('=').append(Objects.toString(record.get(key), "")).append('\n');
        }
        return sb.toString();
    }

    private static final class RowEnvelope {
        final Map<String, String> row;
        final long age;
        final long salaryCents;

        RowEnvelope(Map<String, String> row, long age, long salaryCents) {
            this.row         = row;
            this.age         = age;
            this.salaryCents = salaryCents;
        }
    }
}