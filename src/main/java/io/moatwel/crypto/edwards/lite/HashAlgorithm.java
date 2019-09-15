package io.moatwel.crypto.edwards.lite;

public enum HashAlgorithm {
  SHA_512("SHA-512");

  private String algorithm;

  HashAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  public String getName() {
    return algorithm;
  }
}
