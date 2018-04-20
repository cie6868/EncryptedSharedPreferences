# EncryptedSharedPreferences

 [![Build Status](https://travis-ci.org/cie6868/EncryptedSharedPreferences.svg?branch=master)](https://travis-ci.org/cie6868/EncryptedSharedPreferences)

A wrapper for `SharedPreferences` that provides cryptographic obfuscation and data protection. Requires Android API 19 (KitKat) or higher. Released under the MIT Licence.

## Threat Model

An attacker who has access to the /data/data directory where `SharedPreferences` are stored.

If you need something more advanced you should consider storing sensitive data server-side, where there is a single known system you can design your security measures around.

## Usage

```java
EncryptedSharedPreferences prefs =
	new EncryptedSharedPreferences(new EncryptedSharedPreferencesSettings() {
		public Context context() { return MainActivity.this; }
		public String preferencesName() { return PREFS_NAME; }
		public boolean allowCryptoKeyChange() { return false; }
		public boolean allowInsecureRSAFallback() { return true; }
		public boolean allowAesKeyInMemory() { return true; }
		public boolean allowDebugLogs() { return true; }
	});

EncryptedSharedPreferences.Editor editor = prefs.edit();
editor.putString("TestKey, "TestValue");
editor.putBoolean("TestBoolean", true);
editor.commit();

prefs.getString("TestKey", null);		// outputs TestValue
prefs.getBoolean("TestBoolean" false);		// outputs true
prefs.getFloat("TestKey", 1.1f);		// output 1.1f since TestKey not a float
```

`EncryptedSharedPreferences` supports the same data types as regular `SharedPreferences`: `String`, `Set<String>`, `boolean`, `long`, `float` and `int`. Requesting a key with the wrong data type will return the default value provided. Likewise, requesting the wrong key will also return the default value.

Cryptography can be slow on some devices, so it might be a good practice to run these operations outside the main thread.

For more examples see `MainActivity` in the sample app and `PreferenceTest` in the library.

## Options
| Title | Default | Description | Remarks |
|--|--|--|--|
| `context` |  | Context |  |
| `preferencesName` |  | Name of the XML file used to store data. |  |
| `allowCryptoKeyChange` | `false` | Allow new cryptographic keys to be generated automatically if the existing keys fail to load (e.g. RSA keys have changed so the AES key and salt have to be regenerated). | Keys are always auto-generated if none exist |
| `allowInsecureRSAFallback` | `true` | Allow RSA keys to be stored insecurely if hardware-backed secure storage is not available. | Improves device compatibility at the cost of security |
| `allowAesKeyInMemory` | `true` | Allow the decrypted AES key to be held in memory for the lifetime of the current `EncryptedSharedPreferences`. | Dramatic performance increase at the cost of security |
| `allowDebugLogs` | `false` | Enables logging. | Should be `false` in production |

## Exceptions and Logging

A `CryptoException` will be thrown if there is an error while instantiating `EncryptedSharedPreferences` or storing data.

Errors during data retrieval and storage are silent. Failed retrieval will return the default value provided. `Editor` commits are atomic and a failure will cause all key-value pairs in that `Editor` to remain uncommitted.

Use `allowDebugLogs` to log the causes and stack traces.

## Security

The `SharedPreferences` API stored key-value pairs as plaintext in XML files in the device's internal storage. While these are not immediately accessible to other apps and end users, it is possible to obtain root access and read and modify these files.

In `EncrptedSharedPreferences` keys are hashed and values are encrypted.

Values are encrypted using AES in Galois Counter Mode. The AES key itself is encrypted with RSA (ECB, PKCS1) and stored in regular `SharedPreferences`.

The RSA keys are stored within the `AndroidKeyStore`. All operations in the `AndroidKeyStore` are done within the Trusted Execution Environment (TEE).

Keys in the key-value pairs are hashed using SHA512 and a fixed salt. The hashing is deterministic as long as the salt does not change. The salt is encrypted with AES so that it is difficult for an attacker to calculate hashes themselves.

When reading key-value pairs, hashing and encryption is done on demand. When writing, hashing and encryption is only done once `Editor.commit()` is called. Wherever possible, cryptographic operations are batched together to improve performance.

In the interests of performance, `allowKeyInMemory` is enabled by default so that the AES key does not have to be decrypted each operation. The obvious security risk is that an attacker could observe the key data in memory.

The end result is a `SharedPreferences` XML file that looks like this:

```xml
<map>
	<string name="By7gGc/3PE3fwITUcRfPEWUAt7m7H6UgiBtP4EhoOXZMoj/m5zdqR/aCVSBe6mELvv56hByd7oYS0LASr7LgzQ==">AAAADODdIgLsSFIUiut6thVwgjeCmKjn3ddUAiWQWysi/AOw</string>
	<string name="6YfC3yca8WSDlI4mbdMD6p4SVNpbgU67TSkQd7ORWUcsCUNH4zzNUn3WkIbe9cqAg0m68yDAQQowbschOFe/+g==">AAAADI7RiRL7QUr1cmjCXv1g0j1khWIe2UYliTHLbRXyUJmQhTp/L18zIt6n4ULNQGZIDy8Z</string>
</map>
```

### Caveats

Some devices do not support using the `AndroidKeyStore` or have serious bugs that inhibit its use. For example, [LineageOS had a bug](https://jira.lineageos.org/browse/BUGBASH-590) which affected its build for some devices that I was working with.

As a workaround, RSA keys can be stored in `SharedPreferences` instead by enabling `allowInsecureRSAFallback`. This provides absolutely no security if the attacker knows how to use an RSA key pair. Even so, the library will always attempt to use `AndroidKeyStore` first and only fallback when that fails.

## Performance

Based on rudimentary benchmarking by running sets of operations for 100 cycles. These were repeated a few times and the fastest times are noted below.

| Set of Operations (x 100) | [OnePlus 5](https://www.gsmarena.com/oneplus_5-8647.php) | [Samsung Galaxy S7E](https://www.gsmarena.com/samsung_galaxy_s7_edge-7945.php) |
|--|--|--|
| Storage | 796.72 ms | 2598.12 ms |
| Retrieval | 2178.57 ms | 6105.72 ms |
| Storage with `allowKeyInMemory=true` | 22.56 ms | 12.06 ms |
| Retrieval with `allowKeyInMemory=true` | 2.28 ms | 5.82 ms |

It is clear that RSA operations in the Trusted Execution Environment hamper performance significantly. RSA operations can be minimized using `allowKeyInMemory` to provide faster performance, but at a security cost of holding the AES key in memory for long periods.

These benchmarks are found in `PreferencesTest` in the library code. More algorithm-specific benchmarks are found in `RsaHelperTest`, `LegacyAesCryptoTest` and `KeyHasherTest`

## To Be Implemented

* Add an element of user input to the AES encryption process.
* AES encryption within the Trusted Execution Environment (`AndroidKeyStore`) for devices with Android 23 or higher.
* Implement `OnSharedPreferenceChangeListener` from the `SharedPreferences` interface.
* Some way of tracking keys so we know definitively when they have changed (and all data is invalidated!)

## Questions

Some questions that I asked myself.

### Why extend `SharedPreferences`?

So you can do an drop a `EncryptedSharedPreferences` in place of regular `SharedPreferences` and only have to rewrite the initialization.

### My Eclair/Honeycomb/IceCreamSandwich device is not supported. Why?

Using the `AndroidKeyStore` (read: hardware-backed RSA encryption) requires Android 18 or higher. Using AES in GCM mode requires Android 19 (KitKat) or higher.

### Why not store the AES key directly in the `AndroidKeyStore`?

Because that is only supported on Marshmallow (API 23) or higher. I do intend on adding that soon as the default option for compatible devices soon.

### Why are the keys in key-value pairs hashed and not encrypted?

AES in Galois Counter Mode (GCM) produces different ciphertexts for the same input, so it would be impossible to lookup an key by encrypting the search term. All the keys can be decrypted instead, but that causes an O(n) workload as every key needs to be decrypted each time you want to find a key-value pair.

Hashing allows the same output to be produced as long as the salt is not changed. This allows lookups to be done using the hashed search key. The salt itself is encrypted with AES-GCM so that you can't produce the same hashes outside the library.

### Why SHA512 hashes instead of PBKDF2?

The Java implementation of PBKDF2 is quite slow and the SpongyCastle implementation is still slow enough to hamper performance of the library. Integrating SpongyCastle also adds a hefty dependency to the library. SHA512 isn't as good as PBKDF with 10,000+ iterations, but since it's used obfuscate keys and not protect the data, it seems a decent trade-off.

### Why does `getAll()` throw an `UnsupportedOperationException`?

Since keys are hashed, `getAll()` would return a set of key-value pairs where all the keys are gibberish. I didn't see much point in that.

## Disclaimer

I am not a security expert. Use at your own risk.

If you find a problem or loophole, [open an issue](https://github.com/cie6868/EncryptedSharedPreferences/issues). Please feel free to contribute improvements and bugfixes.
