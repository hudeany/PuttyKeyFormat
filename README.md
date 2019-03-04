# PuttyKeyFormat  
PuttyKeyReader and PuttyKeyWriter (.ppk)  

Class "de.soderer.utilities.PuttyKey":  
Stores the key pair data of a PuttyKey.

Class "de.soderer.utilities.PuttyKeyReader":  
Reads PuTTY key files in ".ppk" format.  
Those files may be encrypted by "aes256-cbc" or unencrypted.  

Class "de.soderer.utilities.PuttyKeyWriter":  
Writes PuTTY keys to ".ppk" format.  
Also writes an unencrypted ".pem" format for usage in OpenSSH.  
For encrypted ".pem" files use PuttyKeyOpenSshHelper, which deoends on the BouncyCastle crypto library.  

For Usage see class "de.soderer.utilities.test.PuttyKeyTest"  
