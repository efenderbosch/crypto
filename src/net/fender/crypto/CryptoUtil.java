/* 
 * Copyright 2008 - 2009 Eric Fenderbosch
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.fender.crypto;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Supports use as POJO and static util by setting System properties. This has
 * been tested with TripleDES and DES.
 * 
 * @TODO Specify UTF-8/UTF-16 charset or allow others?
 * @author Eric Fenderbosch
 */
public class CryptoUtil {

	/**
	 * net.fender.crypto
	 */
	public static final String SYSTEM_PROPERTY_KEY_PREFIX = "net.fender.crypto.";

	public static final int TRIPLE_DES_KEY_SIZE_BYTES = 24;
	public static final int DES_KEY_SIZE_BYTES = 8;

	private static final SecureRandom random = new SecureRandom();
	private static final Base64 base64Codec = new Base64();

	private String algorithm;

	/**
	 * @param algorithm
	 */
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @param base64Key
	 * @return
	 * @throws GeneralSecurityException
	 */
	public Key getKey(String base64Key) throws GeneralSecurityException {
		byte[] keyBytes = Base64.decodeBase64(base64Key.getBytes());
		Key key = new SecretKeySpec(keyBytes, algorithm);
		return key;
	}

	/**
	 * @param keyLength
	 * @return
	 */
	public static String generateRandomBase64Key(int keyLength) {
		byte[] keyBytes = new byte[keyLength];
		random.nextBytes(keyBytes);
		String base64KeyString = new String(base64Codec.encode(keyBytes));
		return base64KeyString;
	}

	/**
	 * Returns a key based on System.getProperties(). Use setSystemPropertyKey
	 * and setSystemPropertyAlgorithm to configure, or manually set System
	 * properties using SYSTEM_PROPERTY_KEY_PREFIX.
	 * 
	 * @param keyName
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Key getSystemPropertyKey(String keyName) throws GeneralSecurityException {
		String base64Key = System.getProperty(SYSTEM_PROPERTY_KEY_PREFIX + keyName);
		String algorithm = System.getProperty(SYSTEM_PROPERTY_KEY_PREFIX + keyName + ".algorithm");
		byte[] keyBytes = Base64.decodeBase64(base64Key.getBytes());
		Key key = new SecretKeySpec(keyBytes, algorithm);
		return key;
	}

	/**
	 * @param keyName
	 * @param base64EncodedKey
	 * @return
	 */
	public static String setSystemPropertyKey(String keyName, String base64EncodedKey) {
		return System.setProperty(SYSTEM_PROPERTY_KEY_PREFIX + keyName, base64EncodedKey);
	}

	/**
	 * @param keyName
	 * @param algorithm
	 * @return
	 */
	public static String setSystemPropertyAlgorithm(String keyName, String algorithm) {
		return System.setProperty(SYSTEM_PROPERTY_KEY_PREFIX + keyName + ".algorithm", algorithm);
	}

	/**
	 * NB: Ciphers are not thread safe. Don't reuse the instance returned by
	 * this method in multiple threads.
	 * 
	 * @param keyName
	 * @param mode
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getSystemPropertyCipher(String keyName, int mode) throws GeneralSecurityException {
		Key key = getSystemPropertyKey(keyName);
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(mode, key);
		return cipher;
	}

	/**
	 * @param base64EncodedKey
	 * @param base64EncodedString
	 * @return
	 * @throws GeneralSecurityException
	 */
	public String decrypt(String base64EncodedKey, String base64EncodedString) throws GeneralSecurityException {
		Key key = getKey(base64EncodedKey);
		return decrypt(key, base64EncodedString);
	}

	public String decrypt(Key key, String base64Encoded) throws GeneralSecurityException {
		byte[] encryptedBytes = Base64.decodeBase64(base64Encoded.getBytes());
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		String decrypted = new String(decryptedBytes);
		return decrypted;
	}

	/**
	 * @param keyName
	 * @param base64Encoded
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static String decryptUsingSystemPropertyKey(String keyName, String base64Encoded)
			throws GeneralSecurityException {
		byte[] encryptedBytes = Base64.decodeBase64(base64Encoded.getBytes());
		Key key = getSystemPropertyKey(keyName);
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		String decrypted = new String(decryptedBytes);
		return decrypted;
	}

	/**
	 * @param key
	 * @param plaintext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public String encrypt(Key key, String plaintext) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedByes = cipher.doFinal(plaintext.getBytes());
		String encrypted = new String(Base64.encodeBase64(encryptedByes));
		return encrypted;
	}

	/**
	 * @param base64EncodedKey
	 * @param plaintext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public String encrypt(String base64EncodedKey, String plaintext) throws GeneralSecurityException {
		Key key = getKey(base64EncodedKey);
		return encrypt(key, plaintext);
	}

	/**
	 * @param keyName
	 * @param plaintext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static String encryptUsingSystemPropertyKey(String keyName, String plaintext)
			throws GeneralSecurityException {
		Key key = getSystemPropertyKey(keyName);
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedByes = cipher.doFinal(plaintext.getBytes());
		String encrypted = new String(Base64.encodeBase64(encryptedByes));
		return encrypted;
	}

	/**
	 * Verify thread safety of org.apache.commons.codec.binary.Base64.
	 * 
	 * @TODO Move this to JUnit test case.
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		byte[][] strings = new byte[10000][];
		// generate a bunch of random "strings"
		for (int i = 0; i < strings.length; i++) {
			// generate a random "string" 32 - 64 bytes long
			byte[] bytes = new byte[random.nextInt(32) + 32];
			random.nextBytes(bytes);
			strings[i] = bytes;
		}
		Runner runner = new Runner(strings);
		for (int i = 0; i < 100; i++) {
			Thread t = new Thread(runner);
			t.start();
		}
	}

	private static class Runner implements Runnable {

		private byte[][] originals;

		public Runner(byte[][] originals) {
			this.originals = originals;
		}

		public void run() {
			for (byte[] original : originals) {
				byte[] encoded = Base64.encodeBase64(original);
				byte[] decoded = Base64.decodeBase64(encoded);
				if (!Arrays.equals(original, decoded)) {
					System.err.println(Thread.currentThread() + " asymetric Base64 encode/decode (not thread safe?) "
							+ new String(original) + " != " + new String(decoded));
				}
			}
		}
	}
}
