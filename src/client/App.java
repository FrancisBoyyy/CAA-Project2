package client;

import client.config.ApplicationConfig;
import client.config.ClientEmployeeIndexStore;
import client.config.KeyManager;
import client.repository.MongoEmployeeRepository;
import client.service.EmployeeService;
import client.service.RecordDecryptor;
import crypto.EncryptionService;
import crypto.aes.DeterministicAesCtr;
import crypto.aes.RandomAesGcm;
import crypto.hom.BoldyrevaOpeCipher;
import crypto.hom.OpeCipher;
import crypto.hom.PaillierCryptosystem;
import crypto.hom.TreeMapOpeCipher;
import crypto.integrityandauthenticity.RecordSigner;
import crypto.integrityandauthenticity.RecordVerifier;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import static client.service.RecordDecryptor.formatCentsAbs;

public final class App {

    public static void main(String[] args) throws Exception {

        ApplicationConfig appConfig = new ApplicationConfig(Path.of("application.properties"));

        Path keysDir = Path.of(appConfig.keysDirectory());
        Files.createDirectories(keysDir);

        KeyManager keyManager = new KeyManager(Path.of(appConfig.keysDirectory()));

        byte[] detAesKey = keyManager.loadOrCreateBytes("detAes.key",   32);
        byte[] detIvKey  = keyManager.loadOrCreateBytes("detIvAes.key", 32);
        DeterministicAesCtr det = new DeterministicAesCtr(detAesKey, detIvKey);

        SecretKey gcmKey = keyManager.loadOrCreateAesKey("gcm.key");
        RandomAesGcm rnd = new RandomAesGcm(gcmKey);

        PaillierCryptosystem.KeyPair paillierKeyPair =
                keyManager.loadOrCreatePaillierKeyPair("paillier.properties");

        EncryptionService encryptionService = new EncryptionService(det, rnd, paillierKeyPair);

        /**
        TreeMapOpeCipher ageOpe = TreeMapOpeCipher.loadOrCreate(keysDir.resolve("age-ope.properties"));
        TreeMapOpeCipher salaryOpe = TreeMapOpeCipher.loadOrCreate(keysDir.resolve("salary-ope.properties"));
         */

        byte[] ageOpeKey    = keyManager.loadOrCreateBytes("age-ope.key",    32);
        byte[] salaryOpeKey = keyManager.loadOrCreateBytes("salary-ope.key", 32);
        OpeCipher ageOpe    = BoldyrevaOpeCipher.forAge(ageOpeKey);
        OpeCipher salaryOpe = BoldyrevaOpeCipher.forSalaryCents(salaryOpeKey);

        ClientEmployeeIndexStore employeeIndexStore =
                ClientEmployeeIndexStore.loadOrCreate(keysDir.resolve("employee-index.tsv"));

        KeyPair    signingKeyPair = keyManager.loadOrCreateEcdsaKeyPair("ecdsa_private.key", "ecdsa_public.key");
        PrivateKey signingPrivKey = signingKeyPair.getPrivate();
        PublicKey  signingPubKey  = signingKeyPair.getPublic();

        byte[] hmacKey = keyManager.loadOrCreateBytes("hmac.key", 32);

        BootstrapClient bootstrapClient = new BootstrapClient(
                encryptionService,
                ageOpe,
                salaryOpe,
                signingPrivKey,
                hmacKey,
                employeeIndexStore
        );

        RecordSigner recordSigner = new RecordSigner(
                hmacKey,
                signingPrivKey
        );

        RecordVerifier verifier = new RecordVerifier(
                hmacKey,
                signingPubKey
        );

        RecordDecryptor decryptor = new RecordDecryptor(
                encryptionService,
                ageOpe,
                salaryOpe,
                employeeIndexStore
        );

        String mongoUri        = appConfig.mongoUri();
        String mongoDatabase   = appConfig.mongoDatabase();
        String mongoCollection = appConfig.mongoCollection();

        try (MongoEmployeeRepository repository =
                     new MongoEmployeeRepository(
                             mongoUri,
                             mongoDatabase,
                             mongoCollection
                     )
        ) {

            EmployeeService service = new EmployeeService(
                    bootstrapClient, repository, encryptionService, verifier, decryptor,
                    recordSigner, salaryOpe);

            System.out.println("Employee DB client ready.");
            System.out.println("Decryption mode : OFF  (records returned as stored in the DB)");
            System.out.println("Type 'help' for commands.");

            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.print("> ");
                String line = scanner.nextLine().trim();

                if (line.isEmpty()) {
                    continue;
                }

                if (line.equalsIgnoreCase("exit") || line.equalsIgnoreCase("quit")) {
                    System.out.println("Bye.");
                    break;
                }

                if (line.equalsIgnoreCase("help")) {
                    printHelp(service.isDecryptionEnabled());
                    continue;
                }

                try {
                    handleCommand(service, line, appConfig);
                } catch (SecurityException e) {
                    System.out.println("[SECURITY] " + e.getMessage());
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }


    private static void handleCommand(
            EmployeeService service,
            String line,
            ApplicationConfig appConfig
    ) throws Exception {

        String[] parts   = line.split("\\s+", 2);
        String   command = parts[0].toLowerCase();
        String   cmdArgs = parts.length > 1 ? parts[1].trim() : "";

        switch (command) {
            case "toggle" -> {
                boolean nowOn = service.toggleDecryption();
                System.out.println("Decryption mode : " + (nowOn ? "ON  (records will be decrypted before display)"
                        : "OFF (records returned as stored in the DB)"));
            }
            case "bootstrap" -> {
                int inserted = service.bootstrapFromCsv(Path.of(appConfig.employeesCsvPath()));
                System.out.println("Inserted " + inserted + " encrypted records.");
            }
            case "count" -> System.out.println("Stored employees: " + service.countEmployees());
            case "find-id" -> printOne(service.findByEmployeeId(cmdArgs));
            case "find-name" -> printOne(service.findByFullName(cmdArgs));
            case "find-dept" -> printMany(service.findByDepartment(cmdArgs));
            case "salary-asc" -> printMany(service.orderedBySalary(true));
            case "salary-desc" -> printMany(service.orderedBySalary(false));
            case "age-asc" -> printMany(service.orderedByAge(true));
            case "age-desc" -> printMany(service.orderedByAge(false));
            case "highest-salary" -> printOne(service.highestSalaryEmployee());
            case "oldest" -> printOne(service.oldestEmployee());
            case "payroll" -> {
                requireArgs(command, cmdArgs);
                long cents = service.totalPayrollForDepartment(cmdArgs);
                System.out.println("Total payroll (cents): " + cents + " (" + formatCentsAbs(cents) + ").");
            }
            case "bonus" -> {
                requireArgs(command, cmdArgs);
                long cents = service.bonusForEmployee(cmdArgs);
                System.out.println("Bonus preview: " + cents + " cents (" + formatCentsAbs(cents) + ")"
                        + "  [read-only — use 'apply-bonus' to persist the new salary]");
            }
            case "bonuses" -> {
                System.out.println("[read-only preview — use 'apply-bonuses' to persist]");
                printMany(service.bonusesForEligibleEmployees());
            }
            case "apply-bonus" -> {
                requireArgs(command, cmdArgs);
                long cents = service.applyBonusForEmployee(cmdArgs);
                System.out.println(
                        "Bonus applied and salary updated in the database. Bonus: " + cents + " cents (" + formatCentsAbs(cents) + ").");
            }
            case "apply-bonuses" -> {
                List<Map<String, Object>> results = service.applyBonusesToEligibleEmployees();
                System.out.println("Bonuses applied and persisted for "
                        + results.size() + " eligible employee(s):");
                results.forEach(System.out::println);
            }
            case "compare-salary" -> {
                String[] pair = cmdArgs.split("\\|", 2);
                if (pair.length != 2) {
                    throw new IllegalArgumentException("Use: compare-salary Name A | Name B");
                }
                int cmp = service.compareSalaryByFullName(pair[0].trim(), pair[1].trim());
                System.out.println("Comparison result: " + cmp);
                System.out.println(cmp < 0 ? "First earns less."
                        : cmp > 0 ? "First earns more."
                          :            "Same salary.");
            }
            case "snapshot" -> {
                String fileName = cmdArgs.isBlank()
                        ? "encrypted-snapshot-" + LocalDate.now() + ".jsonl"
                        : cmdArgs;
                Path snapshotDir = Path.of(appConfig.keysDirectory(), "snapshots");
                Path snapshotFile = snapshotDir.resolve(fileName);
                Path written = service.snapshotEncryptedDatabase(snapshotFile);
                System.out.println("Snapshot written to: " + written.toAbsolutePath());
            }
            default -> System.out.println("Unknown command: " + command);
        }
    }

    private static void requireArgs(String command, String cmdArgs) {
        if (cmdArgs == null || cmdArgs.isBlank()) {
            throw new IllegalArgumentException("Command '" + command + "' needs arguments.");
        }
    }

    private static void printHelp(boolean decryptionOn) {
        String toggleLabel = decryptionOn ? "[currently: ON -> switches to encrypted view]\n"
                : "[currently: OFF -> switches to decrypted view]\n";
        System.out.println("""
                Commands:
                  bootstrap                        Load and encrypt CSV into the database
                  count                            Number of stored employee records
                  find-id <employeeId>             Look up by employee ID
                  find-name <full name>            Look up by full name
                  find-dept <departmentId>         All employees in a department
                  salary-asc                       All employees ordered by salary (low→high)
                  salary-desc                      All employees ordered by salary (high→low)
                  age-asc                          All employees ordered by age (young→old)
                  age-desc                         All employees ordered by age (old→young)
                  highest-salary                   Employee with the highest salary
                  oldest                           Oldest employee
                  payroll <departmentId>           Total payroll for a department (homomorphic)
                  bonus <full name>                Preview 25% bonus for a named employee (read-only)
                  bonuses                          Preview 25% bonuses for all eligible employees (read-only)
                  apply-bonus <full name>          Apply 25% bonus and persist new salary to DB
                  apply-bonuses                    Apply 25% bonus to all eligible employees and persist
                  compare-salary Name A | Name B   Compare salaries of two employees
                  toggle                           Toggle decryption of results""" + toggleLabel + """
                  snapshot [file]                  Export encrypted DB contents to a snapshot file
                  help
                  exit
                 \s""");
    }

    private static void printOne(Map<String, Object> record) {
        if (record == null) {
            System.out.println("No record found.");
        } else {
            System.out.println(record);
        }
    }

    private static void printMany(List<Map<String, Object>> records) {
        if (records == null || records.isEmpty()) {
            System.out.println("No records found.");
        } else {
            records.forEach(System.out::println);
        }
    }
}