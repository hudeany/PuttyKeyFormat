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
This is a pure JAVA 8 class with no special external dependencies.  

## Class "de.soderer.utilities.OpenSshKeyReader"  
Reads OpenSSH key files in ".pem" (PKCS#1, PKCS#8) format.  
Those files may be encrypted by AES-128 or TripleDES or unencrypted.  
This is a pure JAVA 8 class with no special external dependencies.  

## Class "de.soderer.utilities.OpenSshKeyWriter"  
Writes OpenSSH keys to encrypted or unencrypted ".pem" (PKCS#1, PKCS#8) format, using AES-128 or TripleDES key encryption.  
Writes OpenSSH keys to unencrypted ".pem" (PKCS#1) format for usage in OpenSSH.  
This is a pure JAVA 8 class with no special external dependencies.  

For usage see class "de.soderer.utilities.test.PuttyKeyTest" and "de.soderer.utilities.test.OpenSshKeyTest"  
