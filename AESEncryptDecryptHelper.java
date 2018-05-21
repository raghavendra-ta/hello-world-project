
package com.cryptoutils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/* 
 * Source: http://www.novixys.com/blog/java-aes-example/
 */
public class CryptoHelper {
	private String salt;
	private SecretKeySpec skey; 
	private IvParameterSpec ivSpec;
	private static final String TOKEN = "password";
	private int pwdIterations = 65536;
	//private int keySize = 256;
	private int keySize = 128;
	private String keyAlgorithm = "AES";
	private String encryptAlgorithm = "AES/CBC/PKCS5Padding";
	private String secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1";
	
	public CryptoHelper() throws Exception{
		this.salt = getSalt();
		this.skey = getKey();
		this.ivSpec = getIvSpec();
	}
	
private IvParameterSpec getIvSpec() throws FileNotFoundException, IOException{
		
		IvParameterSpec ivspec = null;
		String ivFile = "/tmp/ivstore.dat";
		File ivf = new File(ivFile);
		if(ivf.exists()) {
			byte[] iv = null;
			try {
				iv = Files.readAllBytes(Paths.get(ivFile));
			} catch (IOException e) {
				throw e;
			}
			ivspec = new IvParameterSpec(iv);
		} else {
			SecureRandom srandom = new SecureRandom();
			//The block size required depends on the AES encryption block size. 
			//For the default block size of 128 bits, we need an initialization vector of 16 bytes.
			byte[] iv = new byte[128/8];
			srandom.nextBytes(iv);
			ivspec = new IvParameterSpec(iv);
			
			try (FileOutputStream out = new FileOutputStream(ivFile)) {
			    out.write(iv);
			    out.close();
			} catch (FileNotFoundException e) {
				throw e;
			} catch (IOException e) {
				throw e;
			}
		}
		
		return ivspec;
	}

	private SecretKeySpec getKey() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException {
		String keyFile = "/tmp/keystore.jks";
		File kf = new File(keyFile);
		byte[] keyb = null;
		if(kf.exists()) {
			//Read key from keystore
			try {
				keyb = Files.readAllBytes(Paths.get(keyFile));
			} catch (IOException e) {
				throw e;
			}
		} else {
			//Generate key
/*			KeyGenerator kgen = null;
			try {
				kgen = KeyGenerator.getInstance(keyAlgorithm);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			SecretKey skey = kgen.generateKey();
*/
			//Generate key
			byte[] saltBytes = null;
			try {
				saltBytes = salt.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw e;
			}
			
			SecretKeyFactory skf;
			SecretKey sKey = null;
			try {
				skf = SecretKeyFactory.getInstance(this.secretKeyFactoryAlgorithm);
				PBEKeySpec spec = new PBEKeySpec(TOKEN.toCharArray(), saltBytes, this.pwdIterations, this.keySize);
				sKey = skf.generateSecret(spec);
				//skey = new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);
				keyb = sKey.getEncoded();
			} catch (NoSuchAlgorithmException e) {
				throw e;
			} catch (InvalidKeySpecException e) {
				throw e;
			}
			
			//store the key 
			try (FileOutputStream out = new FileOutputStream(keyFile)) {
			     keyb = sKey.getEncoded();
			    out.write(keyb);
			    out.close();
			} catch (FileNotFoundException e) {
				throw e;
			} catch (IOException e) {
				throw e;
			}
		}
		
		return new SecretKeySpec(keyb, keyAlgorithm);
	}

	private String getSalt() throws FileNotFoundException, IOException {
		File saltFile = new File("/tmp/salt.dat");
		String text = null;
		if(saltFile.exists()) {
			try {
				DataInputStream is = new DataInputStream(new FileInputStream("/tmp/salt.dat"));
				text = is.readUTF();
				is.close();
			} catch (FileNotFoundException e) {
				throw e;
			} catch (IOException e) {
				throw e;
			}
		} else {
			//Generate salt
			SecureRandom random = new SecureRandom();
			byte bytes[] = new byte[20];
			random.nextBytes(bytes);
			text = new String(bytes);
			try {
				DataOutputStream os = new DataOutputStream(new FileOutputStream("/tmp/salt.dat"));
				//os.writeBytes(text);
				os.writeUTF(text);
				os.close();
			} catch (FileNotFoundException e) {
				throw e;
			} catch (IOException e) {
				throw e;
			}			
		}
		return text;
	}
	
	/**
	 * 
	 * @param plainText
	 * @return encrypted text
	 * @throws Exception
	 */
	public String encyrpt(String plainText) throws Exception{
		//AES initialization
		Cipher cipher = Cipher.getInstance(encryptAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE,  skey, ivSpec);
		
		byte[] encryptedText = cipher.doFinal(plainText.getBytes("UTF-8"));
		return new Base64().encodeAsString(encryptedText);
	}
	
	/**
	 * 
	 * @param encryptText
	 * @return decrypted text
	 * @throws Exception
	 */
	public String decrypt(String encryptText) throws Exception {
		String text = null;
		byte[] encryptTextBytes = new Base64().decode(encryptText);

		//decrypt the message
		Cipher cipher = Cipher.getInstance(encryptAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, skey, ivSpec);
		
		byte[] decyrptTextBytes = null;
		try {
			decyrptTextBytes = cipher.doFinal(encryptTextBytes);
			text = new String(decyrptTextBytes);
		} catch (IllegalBlockSizeException e) {
			// TODO: handle exception
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return text;
	}
	
}
