# PuttyKeyFormat (JAVA 8+)
PuttyKeyReader and PuttyKeyWriter (.ppk)  

Class "de.soderer.utilities.PuttyKey":  
Stores the key pair data of a PuTTY Key.

Class "de.soderer.utilities.PuttyKeyReader":  
Reads PuTTY key files in ".ppk" format.  
Those files may be encrypted by "aes256-cbc" or unencrypted.  

Class "de.soderer.utilities.PuttyKeyWriter":  
Writes PuTTY keys to ".ppk" format.  
Also writes an unencrypted ".pem" format for usage in OpenSSH.  

Class "de.soderer.utilities.PuttyKeyOpenSshHelper"
For encrypted ".pem" files use PuttyKeyOpenSshHelper, which depends on the BouncyCastle crypto library (bcpkix-jdk15on-1.61.jar).  

For Usage see class "de.soderer.utilities.test.PuttyKeyTest"  
