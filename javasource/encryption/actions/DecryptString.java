// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package encryption.actions;

import java.security.InvalidAlgorithmParameterException;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import com.mendix.systemwideinterfaces.MendixRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;

public class DecryptString extends CustomJavaAction<java.lang.String>
{
	private java.lang.String value;
	private java.lang.String key;
	private java.lang.String prefix;
	private java.lang.String legacyKey;

	public DecryptString(IContext context, java.lang.String value, java.lang.String key, java.lang.String prefix, java.lang.String legacyKey)
	{
		super(context);
		this.value = value;
		this.key = key;
		this.prefix = prefix;
		this.legacyKey = legacyKey;
	}

	@java.lang.Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		if (this.prefix != null)
			throw new MendixRuntimeException("Prefix should be null when passed to DecryptString, this parameter will be deprecated");
		if (this.value == null)
			return this.value;

		String textPrefix = getPrefix(this.value);
		if (textPrefix == null)
			throw new MendixRuntimeException("Encrypted string does not have a valid prefix.");
		switch (textPrefix) {
			case "AES": return decryptUsingLegacyAlgorithm();
			case "AES2": return decryptUsingGcm();
			case "AES3": return decryptUsingNewAlgorithm();
			default:
				throw new MendixRuntimeException("Invalid prefix encountered when trying to decrypt string: {" + textPrefix + "}");
		}
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 * @return a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "DecryptString";
	}

	// BEGIN EXTRA CODE
	private static final int GCM_TAG_LENGTH = 16; // in bytes
	private static final String LEGACY_PREFIX = "{AES}";
	private static final String LEGACY_PREFIX2 = "{AES2}";
	private static final String NEW_PREFIX = "{AES3}";
	private static final Pattern PREFIX_REGEX = Pattern.compile("^\\{([a-zA-Z0-9]*)\\}.*$");
	private static final String WRONG_KEY_ERROR_MESSAGE = "Cannot decrypt the text because it was either encrypted with a different key or not encrypted at all";

	private String decryptUsingNewAlgorithm() throws Exception {
		if (this.key == null || this.key.isEmpty())
			throw new MendixRuntimeException("Key should not be empty");
		if (this.key.length() != 32)
			throw new MendixRuntimeException("Key length should be 32");

		String[] s = this.value.substring(NEW_PREFIX.length()).split(";");

		if (s.length < 2)
			throw new MendixRuntimeException("Unexpected prefix when trying to decrypt string.");

		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec k = new SecretKeySpec(this.key.getBytes(), "AES"); // ignore Snyk Code warning; false positive

		byte[] iv = Base64.getDecoder().decode(s[0].getBytes());
		byte[] encryptedData = Base64.getDecoder().decode(s[1].getBytes());

		try {
			GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
			c.init(Cipher.DECRYPT_MODE, k, spec);
			return new String(c.doFinal(encryptedData));
		} catch (InvalidAlgorithmParameterException | BadPaddingException ex) {
			if (isEncryptedWithWrongKey(ex.getMessage()))
				throw new MendixRuntimeException(WRONG_KEY_ERROR_MESSAGE);
			else throw ex;
		}
	}

	private String decryptUsingGcm() throws Exception {
		if (this.legacyKey == null || this.legacyKey.isEmpty())
			throw new MendixRuntimeException("Legacy key should not be empty");
		if (this.legacyKey.length() != 16)
			throw new MendixRuntimeException("Legacy key length should be 16");

		String[] s = this.value.substring(LEGACY_PREFIX2.length()).split(";");

		if (s.length < 2)
			throw new MendixRuntimeException("Unexpected prefix when trying to decrypt string using legacy algorithm.");

		Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec k = new SecretKeySpec(this.legacyKey.getBytes(), "AES"); // ignore Snyk Code warning; false positive

		byte[] iv = Base64.getDecoder().decode(s[0].getBytes());
		byte[] encryptedData = Base64.getDecoder().decode(s[1].getBytes());

		try {
			GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
			c.init(Cipher.DECRYPT_MODE, k, spec);
			return new String(c.doFinal(encryptedData));
		} catch (InvalidAlgorithmParameterException | BadPaddingException ex) {
			if (isEncryptedWithWrongKey(ex.getMessage()))
				throw new MendixRuntimeException(WRONG_KEY_ERROR_MESSAGE);
			else throw ex;	
		}
	}
	
	private boolean isEncryptedWithWrongKey(String message) {
		return message.contains("Wrong IV length") ||
				message.contains("Given final block not properly padded") ||
				message.contains("Tag mismatch");
	}

	private String decryptUsingLegacyAlgorithm() throws Exception {
		if (this.legacyKey == null || this.legacyKey.isEmpty())
			throw new MendixRuntimeException("Legacy key should not be empty");
		if (this.legacyKey.length() != 16)
			throw new MendixRuntimeException("Legacy key length should be 16");

		String[] s = this.value.substring(LEGACY_PREFIX.length()).split(";");

		if (s.length < 2)
			throw new MendixRuntimeException("Unexpected prefix when trying to decrypt string using legacy algorithm.");

		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // ignore Snyk Code warning; we decrypt only (for backward compatibility)
		SecretKeySpec k = new SecretKeySpec(this.legacyKey.getBytes(), "AES"); // ignore Snyk Code warning; false positive

		byte[] iv = Base64.getDecoder().decode(s[0].getBytes());
		byte[] encryptedData = Base64.getDecoder().decode(s[1].getBytes());

		try {
			c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
			return new String(c.doFinal(encryptedData));
		} catch (InvalidAlgorithmParameterException | BadPaddingException ex) {
			if (isEncryptedWithWrongKey(ex.getMessage()))
				throw new MendixRuntimeException(WRONG_KEY_ERROR_MESSAGE);
			else throw ex;	
		}
	}

	// try to extract the prefix of an encrypted string
	// returns null if no prefix is found
	private String getPrefix(String text) {
		Matcher m = PREFIX_REGEX.matcher(text);
		return m.find() ? m.group(1) : null;
	}
	// END EXTRA CODE
}
