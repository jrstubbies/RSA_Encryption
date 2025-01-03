# RSA_Encryption

A C++ program implementing a RSA with Cipher Block Chaining (CBC) for TCP client-server applications.
The client sends a encrypted message to the server which decrypts it (both server and client code provided)
using asymmetric keys. Not using an actual CA, so have the server create relevant keys.

//////////////////////////////////////////////////////////////////////////////////////////////////
    
    NOTE:        
        Start up code for the sockets was provided by Massey teacher Napoleon Reyes         
        All RSA-CBC code done by me

//////////////////////////////////////////////////////////////////////////////////////////////////


SERVER:

    - Randomly generates prime numbers (between 5000 - 15000). This gives 'p' and 'q' numbers for 
    server and Certificate Authority (CA). Use these to calculate their 'z' values
    - For server and CA find a prime number that is smaller than their respective 'p' and 'q' values.
    - Use the Euclidean algorithm to ensure 'e' and 'z' values aree co-prime
    - Then use the Extended Euclidean algorithm to find a value for 'd' such that:
            e * d mod z = 1
    - Server sends the public keys to the client
    - Any messages from the client are decrypted using the server's private key and the repeat squares algorithm


CLIENT:

    - Client receives the server public keys
    - Client can now type in a message
    - Using the server's public key and the repeat square algorithm this is encrypted and sent.