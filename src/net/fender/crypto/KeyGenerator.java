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

import java.security.Key;

/**
 * Pass in algorithm, key length and series of plain text Strings to encrypt.
 * Outputs a random BASE64 encoded key and BASE64 encoded encrypted String using
 * the randomly generated key for each plain text String. TripleDES expects a
 * key length of 24 and DES expects a key length of 8.
 * 
 * @author Eric Fenderbosch
 */
public class KeyGenerator {

	public static void main(String[] args) throws Exception {
		if (args.length < 3) {
			System.err
					.println("expected at least 3 arguments: algorithm, key length and one or more plaintext strings to encode");
			System.exit(-1);
		}
		String algorithm = args[0];
		CryptoUtil cryptoUtil = new CryptoUtil();
		cryptoUtil.setAlgorithm(algorithm);
		int keyLength = Integer.parseInt(args[1]);
		String base64Key = CryptoUtil.generateRandomBase64Key(keyLength);
		System.out.println("BASE64 encoded key = " + base64Key);
		Key key = cryptoUtil.getKey(base64Key);

		for (int i = 2; i < args.length; i++) {
			String plaintext = args[i];
			String encrypted = cryptoUtil.encrypt(key, plaintext);
			System.out.println(plaintext + " encrypts to " + encrypted);
		}
	}
}
