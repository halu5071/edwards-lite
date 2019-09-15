package io.moatwel.crypto.edwards.lite;

import java.math.BigInteger;

public class EncodedField {

  private byte[] value;

  EncodedField(byte[] value) {
    this.value = value;
  }

  public byte[] getValue() {
    return value;
  }

  public Field decode() {
    byte[] seed = ByteUtils.reverse(this.value);
    return new Field(new BigInteger(1, seed));
  }
}
