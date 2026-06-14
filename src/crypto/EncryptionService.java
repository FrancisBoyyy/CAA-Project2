package crypto;

import crypto.aes.DeterministicAesCtr;
import crypto.aes.RandomAesGcm;
import crypto.hom.PaillierCryptosystem;

import java.math.BigInteger;
import java.util.Locale;

public final class EncryptionService {

    private final DeterministicAesCtr det;
    private final RandomAesGcm rnd;
    private final PaillierCryptosystem.PublicKey  paillierPublicKey;
    private final PaillierCryptosystem.PrivateKey paillierPrivateKey;

    public EncryptionService(
            DeterministicAesCtr det,
            RandomAesGcm rnd,
            PaillierCryptosystem.KeyPair paillierKeyPair
    ) {
        this.det                = det;
        this.rnd                = rnd;
        this.paillierPublicKey  = paillierKeyPair.publicKey;
        this.paillierPrivateKey = paillierKeyPair.privateKey;
    }

    public String normalizeExact(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }

    public String encryptDeterministic(String value) {
        return det.encrypt(normalizeExact(value));
    }

    public String encryptEmployeeId(String employeeId) {
        return encryptDeterministic(employeeId);
    }

    public String encryptFullName(String fullName) {
        return encryptDeterministic(fullName);
    }

    public String encryptDepartmentId(String departmentId) {
        return encryptDeterministic(departmentId);
    }

    public String encryptSensitiveText(String value) {
        return rnd.encrypt(value == null ? "" : value);
    }

    public String decryptSensitiveText(String ciphertextB64) {
        if (ciphertextB64 == null || ciphertextB64.isBlank()) {
            return "";
        }
        return rnd.decrypt(ciphertextB64);
    }

    public String hashIndex(String exactValue) {
        return Sha256Index.hashHex(normalizeExact(exactValue));
    }

    public BigInteger encryptSalaryCents(long cents) {
        return PaillierCryptosystem.encrypt(cents, paillierPublicKey);
    }

    public long decryptSalaryCents(BigInteger ciphertext) {
        return PaillierCryptosystem.decrypt(ciphertext, paillierPrivateKey).longValueExact();
    }

    public BigInteger addEncryptedSalary(BigInteger c1, BigInteger c2) {
        return PaillierCryptosystem.addCiphertexts(c1, c2, paillierPublicKey);
    }

    public BigInteger multiplyEncryptedSalary(BigInteger cipher, long factor) {
        return PaillierCryptosystem.multiplyByScalar(cipher, factor, paillierPublicKey);
    }
}