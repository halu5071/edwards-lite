package io.moatwel.crypto.edwards.lite;

public class IllegalHexStringException extends RuntimeException {
  private static final long serialVersionUID = 8341784513L;

  IllegalHexStringException(String message) {
    super(message);
  }

  IllegalHexStringException(Throwable throwable) {
    super(throwable);
  }
}
