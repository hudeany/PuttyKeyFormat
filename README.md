# PuttyKeyFormat (JAVA 8)
PuttyKeyReader and PuttyKeyWriter (.ppk)  

## Class "de.soderer.utilities.PuttyKey"  
Stores the key pair data of a PuTTY Key.  
This is a pure JAVA 8 class with no special external dependencies.

## Class "de.soderer.utilities.PuttyKeyReader"  
Reads PuTTY key files in ".ppk" format.  
Those files may be encrypted by "aes256-cbc" or unencrypted.  
This is a pure JAVA 8 class with no special external dependencies.

## Class "de.soderer.utilities.PuttyKeyWriter"  
Writes PuTTY keys to encrypted or unencrypted ".ppk" format.  
Also writes an unencrypted ".pem" format for usage in OpenSSH.  
This is a pure JAVA 8 class with no special external dependencies.

## Class "de.soderer.utilities.PuttyKeyOpenSshHelper"  
To convert a PuTTY key in the encrypted ".pem" files format for usage in OpenSSH use PuttyKeyOpenSshHelper, which depends on the BouncyCastle crypto library (bcprov-jdk15on-1.61.jar and bcpkix-jdk15on-1.61.jar).

For usage see class "de.soderer.utilities.test.PuttyKeyTest"  
