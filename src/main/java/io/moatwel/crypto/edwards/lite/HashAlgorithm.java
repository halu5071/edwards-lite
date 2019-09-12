package io.moatwel.crypto.edwards.lite;

public enum HashAlgorithm {
    SHA3_256("SHA3-256"),

    SHA3_512("SHA3-512"),

    SHA_512("SHA-512");

    private String algorithm;

    HashAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getName() {
        return algorithm;
    }
}
