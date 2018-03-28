# crypt-it
A tool to find out hash for plaintext, plaintext for hashes and to predict which hashing function might be be used if it is presented with a hash. 

![screen shot 2018-03-28 at 5 29 40 pm](https://user-images.githubusercontent.com/28826658/38027875-be6bbcb2-32ae-11e8-8113-eed9c472d225.png)

You have three options to either encrypt the plaintext to hash, decrypt the hash into its plain text or to find what hashing technique might have been used in the first place to create the hash

### 1.) Decrypt the hash
  
  -> To decrypt the hash you have to choose the first option
  
  -> Then select which hashing technique is used to create the hash
  
  -> Once that is done then enter the message you want to decrypt
  
   ![screen shot 2018-03-28 at 5 49 19 pm](https://user-images.githubusercontent.com/28826658/38028377-63c4c824-32b0-11e8-89b4-38a91717965c.png)
 
  
### 2.) Encrypt the plaintext
  
  -> To encrypt the plain text you have to choose the second option
  
  -> Then select the hashing technique you want to use to create the hash
  
  -> Once that is done then enter the plain text you want to encrypt
  
![screen shot 2018-03-28 at 5 29 53 pm](https://user-images.githubusercontent.com/28826658/38027876-bea2d7c4-32ae-11e8-86bf-2a25663b253e.png)

### 3.) Figure out the Hashing technique
  -> To figure out the hashing technique that might have been used choose the third option
  
  -> The paste the hash you want to figure out about and press enter
  
  ![screen shot 2018-03-28 at 5 30 32 pm](https://user-images.githubusercontent.com/28826658/38028376-638d29f0-32b0-11e8-889e-0bfe0c454d6b.png)

Note:-
  
  i) Clone this file on your local machine and then give it the required privileges using chmod 
      
      e.g. $ chmod 755 crypt-it.sh
      
  ii) These are some of the errors you might face, and here is what they mean.
  
  - ERROR CODE : 001   ==>   You exceeded the 400 allowed request per day (please contact me if you need more than that).

  - ERROR CODE : 002   ==>   There is an error in your email / code.

  - ERROR CODE : 003   ==>   Your request includes more than 400 hashes.

  - ERROR CODE : 004   ==>   The type of hash you provide in the argument hash_type doesn't seem to be valid.

  - ERROR CODE : 005   ==>   The hash you provide doesn't seem to match with the type of hash you set.

  - ERROR CODE : 006   ==>   You didn't provide all the arguments, or you mispell one of them.

 

For further issues conact me at - anand1996aditya@gmail.com
