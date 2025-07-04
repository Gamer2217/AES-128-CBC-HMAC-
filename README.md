__In general this is the realization of AES-128 with CBC-HMAC mode.__

__It was made for general use and for educational purpose if you want actually know how AES works(and actually how CBC mode works).__

__Also here are short description how it works:__

1. Firstly you need to install dependencies:

>>sudo apt update
>>sudo apt install libssl-dev(openssl libraries for HMAC generation)
>>sudo apt install gcc(but if you already have a compiler then you can skip this)

2. Compile all files by using this command:

>>gcc AES.c -o AES -lssl -lcrypto

3. Launch it simply:

>>./AES

4.Then there will be two input fields(plaintext and key). Here's an example how it will look:
![image](https://github.com/user-attachments/assets/dd99694d-8933-4534-8218-eb4ce68072f8)

5. After typing text and key press ENTER and you'll have next result:
![image](https://github.com/user-attachments/assets/21d49c9c-6f62-4ad6-ba0e-4492ef51856c)

There we have encrypted message(IV-Encrypted text+padding-HMAC scheme). Also you will have a message of verification that 
"New HMAC generated correctly". That was made as verificator of HMAC as in real systems(if first HMAC!=second HMAC then there's no decryption).
Next line is the view of last block just to check how padding looks in our decrypted text. And then the last one is our decrypted message.

In the header file you have some description of every function so you can read it.
