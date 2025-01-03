//////////////////////////////////////////////////////////////
// TCP SECURE SERVER GCC (IPV6 ready)
//
// Socket code provided by Napoleon Reyes (Massey University)
//
//////////////////////////////////////////////////////////////

#define DEFAULT_PORT "1234" 
#define USE_IPV6 true      //if set to false, IPv4 addressing scheme will be used

#if defined __unix__ || defined __APPLE__
   #include <unistd.h>
   #include <errno.h>
   #include <stdlib.h>
   #include <stdio.h>
   #include <string.h>
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <arpa/inet.h>
   #include <netdb.h> //used by getnameinfo()
   #include <iostream>
   #include <random>
   #include <vector>       // used for the extended euclidean algorithm 
#elif defined __WIN32__
   #include <winsock2.h>
   #include <ws2tcpip.h> //required by getaddrinfo() and special constants
   #include <stdlib.h>
   #include <stdio.h>
   #include <iostream>
   #include <random>    // to get random numbers for the keys
   #include <vector>    // used for the extended euclidean algorithm 
   #define WSVERS MAKEWORD(2,2) // set the version number
   WSADATA wsadata; //Create a WSADATA object called wsadata. 
#endif


#define BUFFER_SIZE 500
#define RBUFFER_SIZE 256
using namespace std;



//*******************************************************************
// VALUES FOR CA AND SERVER KEYS     -> values are long long as extended euclidean wont work with negative
//                                        numbers introduced by using unsigned ints
//********************************************************************
long long dCA, eCA, nCA = 0;           // Certificate Authority keys. Setting nCA to 0 to ensure get a larger value for nCA when calculating values
long long eServer, dServer, nServer;   // server's private and public keys
long long p, q, z;                     // other values required for RSA -> resuse for both key types
long long nonce;                       // hold the DECRYPTED nonce value from the client



//*******************************************************************
// FUNCTIONS
//*******************************************************************
void printBuffer(const char *header, char *buffer){
	cout << "------" << header << "------" << endl;
	for(unsigned int i=0; i < strlen(buffer); i++){
		if(buffer[i] == '\r'){
		   cout << "buffer[" << i << "]=\\r" << endl;	
		} else if(buffer[i] == '\n'){
		   cout << "buffer[" << i << "]=\\n" << endl;	
		} else {   
		   cout << "buffer[" << i << "]=" << buffer[i] << endl;
		}
	}
	cout << "---" << endl;
}


// Helper function to determine if a number is a prime or not. Used for 'p' and 'q'
bool isPrime(long long num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    
    // iterate only up to the square root of 'num'
    for (long long i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) {
            return false;
        }
    }
    return true;
}


// Return a large prime number
long long get_prime() {
   
   // Create a random number generator with some arbitrary fixed seed
   random_device rd;                               
   default_random_engine gen(rd()); 
    
   // Possible prime numbers within range of 5K and 15K
   uniform_int_distribution<> distribution(5000, 15000);

   bool prime = false;
   long long randomNum;

   // keep getting random number until is a prime
   while (!prime){
      randomNum = distribution(gen);        
      prime = isPrime(randomNum);
   }
   return randomNum;
}


// Tests if 'e' and 'z' are coprime using Euclidean algorithm.
bool euclidean(long long div) {
   long long dividend = z;
   long long divisor = div;           // holds value from the get_e() function.
   long long remainder, quotient;     

   // stop when the remainder turns to 0
   while(true) {        
      quotient = dividend / divisor;        
      remainder = dividend % divisor;
      if(remainder == 0) {
         break;
      }

      dividend = divisor;
      divisor = remainder;
   }

   // when remainder is 0 and the divisor is 1, it means that e and z are co-primes.
   if(remainder == 0 && divisor == 1) {
      return true;
   }
   return false;
}


// This gets a valid value for 'e'. Calls 'euclidean' function to ensure is coprime
long long get_e(long long local_n) {
   
   // Create a random number generator engine using arbitrary fixed seed
   random_device rd;                               
   default_random_engine gen(rd()); 
   
   // Possible 'e' value within the range of 5K - 10K
   uniform_int_distribution<> distribution(5000, 10000);
   bool valid = false;     
   long long local_e = distribution(gen);     // initial e value. If invalid then will get new random number in loop

   while(!valid) {
      // If 'local_e' is different to 'p' and 'q', and less than 'n' use Euclidean Algorithm to see if 'e' and 'z' are coprime
      if (local_e < local_n || (local_e != q && local_e != p)) {
         valid = euclidean(local_e);
         if(valid) {
            break;
         } else {
            local_e++;     // if local_e becomes bigger than n, will end up picking new number next iteration.
         }       
      } 

      // if 'local_e' is is the greater than/same as 'n', OR is same as 'p' or 'q' then just increment
      else {
         local_e++;
      }
   }
   return local_e;     // only returns a valid number value for e
}


// Returns a value for d ensuring     "ed mod z = 1"
long long extended_euclidean(long long local_e) {
   vector<long long> xValues = {1, 0};    // initialise the x values
   vector<long long> dValues = {0, 1};    // initialise the d (y) values
   vector<long long> kValues = {0};       // set first value to 0, never actually use this
   vector<long long> wValues = {z, local_e};    // first element is value of z, second is value of e. ARE CO-PRIMES

   int i = 1;  // Start with index 1 as need to set k[1] first.

   // update quotient(k), x, d(y), and gcd(w) values. Push new value to end of vector
   while (true) {
      kValues.push_back(wValues[i-1] / wValues[i]);  
      i++;
      xValues.push_back(xValues[i-2] - (kValues[i-1] * xValues[i-1]));
      dValues.push_back(dValues[i-2] - (kValues[i-1] * dValues[i-1]));
      wValues.push_back(wValues[i-2] - (kValues[i-1] * wValues[i-1]));

      // stop when gcd(w) is 1
      if(wValues[i] == 1) {
         break;
      }
   }

   // if d(y) value is negative then add value of z to make positive
   if(dValues[i] < 0) {
      dValues[i] = dValues[i] + z;
   }
   return dValues[i];
}


// function to set the values of the Certificate authority key values 
void set_CA_Keys() {
   
   // nCA needs to be bigger than nServer for the encryption/decryption to work. Loop until get appropriate numbers
   while(nCA < nServer) {
      p = get_prime();
      q = get_prime();
      
      // If p and q are the same then get a new q value
      while(p == q){
         q = get_prime();
      }

      nCA = p * q;
   }
   
   z = (p-1)*(q-1);
   eCA = get_e(nCA);
   dCA = extended_euclidean(eCA);
}


// function to set the values of the server's private and public keys 
void set_server_keys() {
   p = get_prime();
   q = get_prime();
   
   // If p and q are the same then get a new q value
   while(p == q){
      q = get_prime();
   }

   nServer = p * q;
   z = (p-1)*(q-1);
   eServer = get_e(nServer);
   dServer = extended_euclidean(eServer);
}


// function to encrypt and decrypt a value using server's keys
long long repeatSquare(long long x, long long e, long long local_n) {
	long long y = 1;
	while(e > 0) {
		if((e % 2) == 0) {
			x = (x * x) % local_n;
			e = e / 2;
		} else {
			y = (x * y) % local_n;
			e = e - 1;
		}
	}
	return y;
}


// Take in encrypted char, and return the decrypted char
char cbc_decrypt(long long num) {

   // decrypt the char using the servers private key, then XOR with current nonce
   long long decrypt_char = repeatSquare(num, dServer, nServer);
   long long result = decrypt_char ^ nonce;
   
   // nonce becomes the previous encrypted char value
   nonce = num;

   // convert this value from ASCII into char and return.
   char c = static_cast<char>(result);
   return c;
}




//*******************************************************************
//MAIN
//*******************************************************************
int main(int argc, char *argv[]) {
   printf("\n==================== <<< SECURE TCP SERVER >>> ====================\n");
	printf("==================== <<< Myles Stubbs >>> ====================\n\n");


   // Initialise variables and socket information.
	struct sockaddr_storage clientAddress;
	char clientHost[NI_MAXHOST]; 
	char clientService[NI_MAXSERV];
	
   char send_buffer[BUFFER_SIZE], receive_buffer[RBUFFER_SIZE];
   int n, bytes, addrlen, count;
	char portNum[NI_MAXSERV];


   #if defined __unix__ || defined __APPLE__
      int s,ns;
   #elif defined _WIN32
      SOCKET s, ns;

   //********************************************************************
   // WSSTARTUP
   //********************************************************************
   int err;
	
   err = WSAStartup(WSVERS, &wsadata);
   if (err != 0) {
      WSACleanup();
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
      printf("WSAStartup failed with error: %d\n", err);
		exit(1);
   }

	
   //********************************************************************
   // Confirm that the WinSock DLL supports 2.2.        
   //********************************************************************
    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        exit(1);
    }
    else{
		  printf("\nThe Winsock 2.2 dll was initialised.\n");
	 }
	 
   #endif

   //********************************************************************
   // set the socket address structure.
   //********************************************************************
   struct addrinfo *result = NULL;
   struct addrinfo hints;
   int iResult;


   //********************************************************************
   // STEP#0 - Specify server address information and socket properties
   //********************************************************************
   memset(&hints, 0, sizeof(struct addrinfo));

   if(USE_IPV6){
      hints.ai_family = AF_INET6;  
   } else { 
      hints.ai_family = AF_INET;
   }	 

   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;
   hints.ai_flags = AI_PASSIVE;          

   // Resolve the local address and port to be used by the server
   if(argc==2){	 
      iResult = getaddrinfo(NULL, argv[1], &hints, &result); //converts human-readable hostnames/IP's into linked list of struct addrinfo structures
      sprintf(portNum,"%s", argv[1]);
      printf("\nargv[1] = %s\n", argv[1]); 	
   } else {
      iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); 
      sprintf(portNum,"%s", DEFAULT_PORT);
      printf("\nUsing DEFAULT_PORT = %s\n", portNum); 
   }

   #if defined __unix__ || defined __APPLE__
      if (iResult != 0) {
         printf("getaddrinfo failed: %d\n", iResult);
         
         return 1;
      }	 
   #elif defined _WIN32
      if (iResult != 0) {
         printf("getaddrinfo failed: %d\n", iResult);

         WSACleanup();
         return 1;
      }	 
   #endif

   //********************************************************************
   // STEP#1 - Create welcome SOCKET
   //********************************************************************

   #if defined __unix__ || defined __APPLE__
      s = -1;
   #elif defined _WIN32
      s = INVALID_SOCKET; //socket for listening
   #endif

   // Create a SOCKET for the server to listen for client connections
   s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

   //check for errors in socket allocation
   #if defined __unix__ || defined __APPLE__
      if (s < 0) {
         printf("Error at socket()");
         freeaddrinfo(result);    
         exit(1);//return 1;
      }

   #elif defined _WIN32
      if (s == INVALID_SOCKET) {
         printf("Error at socket(): %d\n", WSAGetLastError());
         freeaddrinfo(result);
         WSACleanup();
         exit(1);//return 1;
      }
   #endif


   //********************************************************************
   //STEP#2 - BIND the welcome socket
   //********************************************************************

   // bind the TCP welcome socket to the local address of the machine and port number
   iResult = bind(s, result->ai_addr, (int)result->ai_addrlen);

   #if defined __unix__ || defined __APPLE__ 
      if (iResult != 0) {
         printf("bind failed with error");
         freeaddrinfo(result);
         close(s);
         return 1;
      }

   #elif defined _WIN32 
      if (iResult == SOCKET_ERROR) {
         printf("bind failed with error: %d\n", WSAGetLastError());
         freeaddrinfo(result);
         closesocket(s);
         WSACleanup();
         return 1;
      }
   #endif    
	 
	freeaddrinfo(result); //free the memory allocated by the getaddrinfo 

	
   //********************************************************************
   //STEP#3 - LISTEN on welcome socket for any incoming connection
   //********************************************************************
   #if defined __unix__ || defined __APPLE__ 
      if (listen( s, SOMAXCONN ) < 0 ) {
         printf( "Listen failed with error\n");
         close(s);
         exit(1);
      } 

   #elif defined _WIN32 	 
      if (listen( s, SOMAXCONN ) == SOCKET_ERROR ) {
         printf( "Listen failed with error: %d\n", WSAGetLastError() );
         closesocket(s);
         WSACleanup();
         exit(1);
      } 
   #endif   


   //*******************************************************************
   //SET THE KEY VALUES FOR THE SERVER AND THE CA
   //*******************************************************************
   set_server_keys();   // get server values first
   set_CA_Keys();       // get Certificate Authority keys, ensuring nCA < nServer
   


   //*******************************************************************
   //INFINITE LOOP   - LISTEN FOR ANY CLIENTS
   //*******************************************************************
   while (1) {  
      printf("\n<<<SERVER>>> is listening at PORT: %s\n", portNum);
      addrlen = sizeof(clientAddress); 
		
      //********************************************************************
      //NEW SOCKET newsocket = accept
      //********************************************************************
      #if defined __unix__ || defined __APPLE__ 
            ns = -1;
      #elif defined _WIN32       
            ns = INVALID_SOCKET;
      #endif	   


      //********************************************************************	
      // STEP#4 - Accept a client connection.  
      //********************************************************************

      #if defined __unix__ || defined __APPLE__ 
         ns = accept(s,(struct sockaddr *)(&clientAddress),(socklen_t*)&addrlen); //IPV4 & IPV6-compliant
         if (ns < 0) {
            printf("accept failed\n");
            close(s);
            
            return 1;
         }
      #elif defined _WIN32 
         ns = accept(s,(struct sockaddr *)(&clientAddress),&addrlen); //IPV4 & IPV6-compliant
         if (ns == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            closesocket(s);
            WSACleanup();
            return 1;
         }
      #endif

	   printf("A <<<CLIENT>>> has been accepted.\n");
		
	   memset(clientHost, 0, sizeof(clientHost));
      memset(clientService, 0, sizeof(clientService));
      getnameinfo((struct sockaddr *)&clientAddress, addrlen, clientHost, sizeof(clientHost),
                    clientService, sizeof(clientService), NI_NUMERICHOST);
		
      printf("Connected to <<<Client>>> with IP address:%s, at Port:%s\n\n",clientHost, clientService);
		



      //********************************************************************		
      // SEND CLIENT PUBLIC CA KEYS
      //********************************************************************
      printf("\n******************************   KEYS GENERATED FOR THIS SESSION  ******************************\n");
      printf("\nThe Certificate Authority keys:  eCA = %lld    nCA = %lld    dCA = %lld\n", eCA, nCA, dCA);
      printf("The Server's private key:   eServer = %lld,  nServer = %lld\n", dServer, nServer);
      printf("The Server's public key:    dServer = %lld,  nServer = %lld\n", eServer, nServer);
      
      printf("\n\n******************************  SENDING KEYS AND RECEIVING NONCE  ******************************\n");

      // Before anything else happens, send the client the public CA key
      count = snprintf(send_buffer, BUFFER_SIZE, "CA %lld %lld\n", eCA, nCA);       
      if(count >= 0 && count < BUFFER_SIZE) {
         bytes = send(ns, send_buffer, strlen(send_buffer), 0);
      }
      if(bytes < 0) break;

      printf("\n----> Sending Certificate Authority's public key:  (%lld,  %lld)\n", eCA, nCA);


      //********************************************************************		
      // ENCRYPT THE SERVER'S PUBLIC KEY AND SEND TO CLIENT
      //********************************************************************
      long long encrypted_e, encrypted_n;
      encrypted_e = repeatSquare(eServer, dCA, nCA);     // encrypted public key value
      encrypted_n = repeatSquare(nServer, dCA, nCA);     // encrypted modulus value 

      // send the encrypted server's public key dCA(e, n)
      count = snprintf(send_buffer, BUFFER_SIZE, "PUBLIC_KEY %lld %lld\n", encrypted_e, encrypted_n);    
      if(count >= 0 && count < BUFFER_SIZE) {
         bytes = send(ns, send_buffer, strlen(send_buffer), 0);
      }
      if(bytes < 0) break;

      // print encrypted version of the server's public key
      printf("\nThe server's plaintext public key: %lld,  %lld\n", dServer, nServer);
      printf("----> Sending server's encrypted public key:  PUBLIC_KEY [%lld, %lld]\n", encrypted_e, encrypted_n);



      //********************************************************************		
      // RECEIVE THE CLIENT'S ACK, AND DECRYPT THE NONCE
      //********************************************************************
      while(true) {
         
         int i = 0;
         while (1) {
            bytes = recv(ns, &receive_buffer[i], 1, 0);
            if ((bytes < 0) || (bytes == 0)) break;
					 
            if (receive_buffer[i] == '\n') { /*end on a LF, Note: LF is equal to one character*/  
               receive_buffer[i] = '\0';
               break;
            }
            if (receive_buffer[i] != '\r') i++; /*ignore CRs*/
         
         }

         // Receive the clients ACK for sending public key
         if(strncmp(receive_buffer, "ACK", 3) == 0) {
            int ack_value;                               // store the ACK code
            int scannedItems = sscanf(receive_buffer, "ACK %d", &ack_value);
            
            if(scannedItems == 1 && ack_value == 226) {
               printf("Received ACK from client: ACK 226;   Public key successfully received.\n");
            } else {
               printf("ERROR:  Failed to recieve a positive ACK from client\n");
               break;
            }
         }

         // Receive the client's ENCRYPTED nonce
         if(strncmp(receive_buffer, "NONCE", 5) == 0) {
            long long encrypt_nonce;                     
            int scannedItems = sscanf(receive_buffer, "NONCE %lld", &encrypt_nonce);
            
            // Decrypt the nonce value using the server's private key.
            if(scannedItems == 1) {
               printf("\nReceived encrypted packet:  NONCE %lld\n", encrypt_nonce);
               nonce = repeatSquare(encrypt_nonce, dServer, nServer);
               
               printf("The decrypted nonce value is:   %lld\n", nonce);           
               printf("----> Sending ACK 220; Nonce successfully received\n");
               
               sprintf(send_buffer, "ACK 220\n");
               bytes = send(ns, send_buffer, strlen(send_buffer), 0);
               
               // check that the message was sent ok
               if(bytes <= 0) {
                  printf("receiving keys has failed\n");
                  #if defined _WIN32
                     WSACleanup();
                  #endif
                  exit(1);
               } 
               
               break;      // break the receive loop when have received and acknowledged the nonce
            }
         }
      }




      //********************************************************************		
      // LOOP TO GET THE CLIENT'S ENCRYPTED MESSAGES
      //******************************************************************** 

	   printf("\n\n----------------------------------------------------------------------\n");
	   printf("The <<< SERVER >>> is waiting to receive messages.\n");
      
      
      // As client/server encrypts/decrypts char-by-char, these are used to hold the entirety of the message
      string decrypted_message = "";
      string encrypted_message = "";
      while (1) {

         //********************************************************************
         //RECEIVE one command (delimited by \r\n)
         //********************************************************************
         n = 0;
         while (1) {
            bytes = recv(ns, &receive_buffer[n], 1, 0);
            if ((bytes < 0) || (bytes == 0)) break;
					 
            if (receive_buffer[n] == '\n') { /*end on a LF, Note: LF is equal to one character*/  
               receive_buffer[n] = '\0';
               break;
            }
            if (receive_buffer[n] != '\r') n++; /*ignore CRs*/
         }
			
         if ((bytes < 0) || (bytes == 0)) break;


         //********************************************************************
         //PROCESS REQUEST
         //********************************************************************	
         
         // This indicates the end of the message
         if(strcmp(receive_buffer, "\0") == 0) {
            
            // convert string to a c style string
            const char *decrypted_str = decrypted_message.c_str();
            const char *encrypted_str = encrypted_message.c_str();

            printf("The fully encrypted message is:   %s\n", encrypted_str);
            printf("The fully decrypted message is:   %s\n", decrypted_str);

            // reset the 'decrypted_message' and 'encrypted_message" strings
            decrypted_message = "";
            encrypted_message = "";
         } 

         // If not the end of the message, get each char and decrypt to build up the message
         else {
            // extract the encrypted character from the receive buffer
            long long encrypted_char;
            int scannedItems = sscanf(receive_buffer, "%lld", &encrypted_char); 
            
            printf("\nReceived the encrypted char value:  %lld\n", encrypted_char);
            
            // decrypt the char with cbc
            if(scannedItems == 1) {
               char decrypted_char = cbc_decrypt(encrypted_char);
               printf("The decrypted char was an   %c\n", decrypted_char);

               // concat this char to the overall message
               decrypted_message += decrypted_char;
               encrypted_message += to_string(encrypted_char);

            } else {
               printf("ERROR:  failed to extract the encrypted char. Exiting.\n");
               break;
            }
         }	
      }
   
      //********************************************************************
      //CLOSE SOCKET
      //********************************************************************
	  

      #if defined __unix__ || defined __APPLE__ 
            int iResult = shutdown(ns, SHUT_WR);
            if (iResult < 0) {
               printf("shutdown failed with error\n");
               close(ns);
               exit(1);
            }
            close(ns);

      #elif defined _WIN32 
            int iResult = shutdown(ns, SD_SEND);
            if (iResult == SOCKET_ERROR) {
               printf("shutdown failed with error: %d\n", WSAGetLastError());
               closesocket(ns);
               WSACleanup();
               exit(1);
            }	

            closesocket(ns);
      #endif      				
		
      printf("\ndisconnected from << Client >> with IP address:%s, Port:%s\n",clientHost, clientService);
   	printf("=============================================");
		
   } //main loop end

   //***********************************************************************
   #if defined __unix__ || defined __APPLE__ 
      close(s);
   #elif defined _WIN32 
      closesocket(s);
      WSACleanup(); /* call WSACleanup when done using the Winsock dll */
   #endif
      
   return 0;
}


