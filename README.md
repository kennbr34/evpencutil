# EVPENCUTIL - EVP Encryption Utility

A GTK3 and CLI file encryption utility using OpenSSL's EVP library

# Dependencies
OpenSSL >= 1.1.*

(For GUI only)

GTK >= 2.91 development files

pkg-config

(For Makefile)

automake >= 1.15.1

# Platforms

All common GNU/Linux distributions

Other POSIX compatible systems with some minor tweaking of the source and manual compilation

Probably Windows if cross-compiled with MinGW, but untested

# Compilation

Command-line iterface:

gcc src/cli.c src/crypt.c src/lib.c src/workthread.c -o ./bin/evpencutil-cli -lcrypto

Graphical interface:

gcc -Dgui \`pkg-config --cflags gtk+-3.0\` src/gui.c src/crypt.c src/lib.c src/workthread.c -o ./bin/evpencutil-gui \`pkg-config --libs gtk+-3.0\` -lcrypto

Or with autotools/automake

./configure

make

*Note* May need to run autoreconf if your autotools version is greater than 1.15.1

# Details

This program provides a graphical and command-line interface to use OpenSSL's EVP library for symmetric file encryption. The aim is to provide AEAD (Authenticated Encryption and Associated Data) encryption via AES-256-CTR-HMAC-SHA512, as well as sane KDF (Key Derivation Function) choices via scrypt. OpenSSl's official 'enc' program still relies on PBKDF2 with a very low iteration count, and as well does not provide AEAD.

AEAD with HMAC was chosen over AES-GCM, AES-CCM, and ChaCha20-Poly1305 for maximum useability of OpenSSL's library of ciphers. Using HMAC also allows for the use of other encryption or digest algorithms like ChaCha20 or SHA3/BLAKE. It's also unclear to me if OpenSSL's AEAD ciphers can actually authenticate data before performing any decryption operations, but because there is an 'update' function and a 'final' function and only the latter returns an error value if authentication failed, then it doesn't seem possible that they do. This means that they cannot follow the Encrypt-then-MAC strategy like using other ciphers in conjunction with HMAC can. This also becomes crucial for the program to be able to process data via standard input and output.

The progrm also makes use of HKDF to derive separate keys from the key derived from a user password, or supplied as a keyfile. Aside from the general practice of deriving a different HMAC key, if the user derives a key with a password and also supplies a keyfile, HDKF is used to derive an encryption key dependent on both secrets. If a password and keyfile are provided, the keyfile is hashed and that hash is used by HKDF along with the key derived by scrypt in order to create an encrption key that relies on both secrets. If only a keyfile is provided, HKDF is still used, but instead the first n bytes (equal to EVP_MAX_KEY_LENGTH) of the keyfile are used along with the hash of the entire file in HKDF to derive an encryption key; this also ensures that if a user specifies a message digest which produces an output smaller than the keysize required by the chosen encryption algorithm, that HKDF will expand it into a key of EVP_MAX_KEY_LENGTH size.

Other considerations made are the use of HMAC to create a keyed-hash for password verification. In many applications, a small amount of known-plaintext is inserted in the cipher-text so that a successful decryption can be detected. However, this also breaks the abiliity of the program to refuse to decrypt any cipher-text which doesn't pass authenticity and introduces known plain-text. Another approach is to simply rely on the authenticity check with HMAC, since an incorrect password would derive an incorrect key, and thus authenticity could not be confirmed. However, that approach makes it impossible to differentiate between an incorrect password, and a unauthentic cipher-text, so HMAC is used separately on the password itself and the resulting keyed hash is attached to the file along with the Message Authentication Code.

Other miscellaneous technical considerations include buffered input/output, with user-defined buffer sizes. Both the file encryption/decryption is able to be buffered, as well as the authenticity check on the ciphertext. The program can measure its own data throughput for the user to tweak these settings to the most optimal, but they default to 1 MB. Lastly, the scrypt work factors are able to be specificed, as well as other message digest algorithms. Though scrypt itself will use its own hash function, HMAC and HKDF will use the user-defined digest algorithm. There were many other options that could have been user-configurable, for example the salt size, but these were kept to defaults so as to not over-complicate the interface. Accompanying the user-specified options is a header containing those choices, so that the user does not need to remember what they specified upon decryption.

The buffered input/output also allows to place MACs incrementally throughout the file, which will allow the ability to process data through standard input and output and still maintain an Encrypt-then-MAC form of authentication. Otherwise, if a single MAC was used for the entire cipher-text, the need to seek to the end to read it, then seek backwards to check the ciphter-text against it would not be possible with stdin or stdout since they are data streams and not files. That would prevent being able to do something like pipe the output of 'tar' into the program in order to make an an encrypted tarball. The buffer size will also dictate the amount of data between MACs, and each MAC will be computed on not only the ciphter-text and associated data, but also HMAC will compute this MAC with a key derived from HKDF using the previou chunk's HMAC key as an "info" parameter. Finally, the buffer size as dictated by the amount that was able to be read is also computed as part of the MAC. This method is similar to the approach used in Monocypher to enforce chunk sequence, and to detect message truncation.

The data format of a file encrypted with this program will be as so:
```
|                     "evpencutil" string                            |
|                EVP cipher algorithm string                         |
|                EVP digest algorithm string                         |
|                           salt                                     |
|        scrypt work factors as 32-bit integers                      |
|            buffer-size as 32-bit integers                          |
|     password keyed-hash produced by HMAC-SHA512                    |
|                   _______________                                  |_
|         buffer-size-amount of ciphter-text                         |
|MAC with EVP_MD_MAX_LENGTH-MAC-length bytes of padding              |(plain-text-file-size / buffer-size) times
|                   _______________                                  |_
|         (buffer-size % plain-text-file-size) amount of ciphter-text|
|MAC with EVP_MD_MAX_LENGTH-MAC-length bytes of padding              |
|                  ________________                                  |
```
Each MAC is computed against the "evpencutil" string, algorithm strings, salt, scrypt work integers, buffer-size, password's keyed-hash, and the buffer-size the time of each chunk-computation. This will produce n * ((buffer-size/plain-text-file-size) * EVP_MD_MAX_LENGTH) amount of bytes in overhead, but this is neglibible unless encrypting very large amounts of data with very small buffer sizes. With defaults, it will essentially be EVP_MD_MAX_LENGTH bytes per megabyte of plaintext.

Finally, the GUI is also able to be driven via the command-line options. This was done mostly for testing purposes, so that various options and configurations could be tested with both versions of the program.

# Examples

Encrypt a file using a password 'password' and a keyfile named 'keyfile'

    evpencutil-cli -e -i file -o file.enc -p password -k keyfile

Do the previous but with non-default scrypt work factors

    evpencutil-cli -e -i file -o file.enc -p password -k keyfile -w N=1024,p=2

Do the previous but with a messge buffer of 64 megabytes

    evpencutil-cli -e -i file -o file.enc -p password -k keyfile -w N=1024,p=2 -s message_buffer=64m

Do the previous but use chacha20 instead of AES

    evpencutil-cli -e -i file -o file.enc -p password -k keyfile -w N=1024,p=2 -s message_buffer=64m -c chacha20
    
Do the previous but enter the password via prompt instead of as a command line argument

    evpencutil-cli -e -i file -o file.enc -P -k keyfile -w N=1024,p=2 -s message_buffer=64m -c chacha20
    
Do the previous but verify the password entered by prompt

    evpencutil-cli -e -i file -o file.enc -P -V -k keyfile -w N=1024,p=2 -s message_buffer=64m -c chacha20
    
Do the previous but display the password as it's typed instead of verifying it

    evpencutil-cli -e -i file -o file.enc -P -D -k keyfile -w N=1024,p=2 -s message_buffer=64m -c chacha20
    
Decrypt the previously created file (assume the password entered at prompt was 'password')

    evpencutil-cli -d -i file.enc -o file.plain -P -k keyfile
    
Perform the same decryption but launch with the GUI instead

    evpencutil-gui -d -i file.enc -o file.plain -p password -k keyfile
    
Do the previous but close the GUI upon completion

    evpencutil-gui -q -d -i file.enc -o file.plain -p password -k keyfile
    
You can encrypt a tarball from standard input

	tar cf - directory | evpencutil-cli -e -i - -o directory.tar.chacha20 -p password -c chacha20
	
Or extract it

	evpencutil-cli -e -i directory.tar.chacha20 -o - -p password | tar xf -
	
A key generator's output can be read in as the keyfile from stdin

	keygen | evpencutil-cli -e -i file -o file.enc -p password -k -
	
To encrypt with chacha20 and then pipe that to the program to encrypt with aes-256-ctr

    evpenctutil-cli -e -i file -o - -p password -c chacha20 | evpenctutil-cli -e -i - -o file.enc -p password2 -c aes-256-ctr

To decrypt:

    evpenctutil-cli -d -i file.enc -o - -p password2 | evpenctutil-cli -d -i - -o file.plain -p password
