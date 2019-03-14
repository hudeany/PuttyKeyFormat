# PuttyKeyFormat (JAVA 8)
PuttyKeyReader and PuttyKeyWriter (.ppk)  
Supported ciphers:  
- ss-rsa (RSA)  
- ssh-dss (DSA)  
- ssh-ecdsa (EC)

## Class "de.soderer.utilities.PuttyKey"  
Stores the key pair data of a PuTTY Key.  
This is a pure JAVA 8 class with no special external dependencies.

## Class "de.soderer.utilities.PuttyKeyReader"  
Reads PuTTY key files in ".ppk" format.  
Those files may be encrypted by "aes256-cbc" or unencrypted.  
This is a pure JAVA 8 class with no special external dependencies.

## Class "de.soderer.utilities.PuttyKeyWriter"  
Writes PuTTY keys to encrypted or unencrypted ".ppk" format.  
Writes PuTTY keys to encrypted or unencrypted ".pem" (PKCS#8) format, using AES-128 or TripleDES key encryption.  
Writes PuTTY keys to unencrypted ".pem" format for usage in OpenSSH.  
This is a pure JAVA 8 class with no special external dependencies.

For usage see class "de.soderer.utilities.test.PuttyKeyTest"  
