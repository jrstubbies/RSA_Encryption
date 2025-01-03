//////////////////////////////////////////////////////////////
// TCP SECURE SERVER GCC (IPV6 ready)
//
// Socket code provided by Napoleon Reyes (Massey University)
//
//////////////////////////////////////////////////////////////

#define DEFAULT_PORT "1234" 
#define USE_IPV6 true  //if set to false, IPv4 addressing scheme will be used

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
	#include <random>    // to get random nonce value
	#include <vector>
#elif defined __WIN32__
  	#include <winsock2.h>
  	#include <ws2tcpip.h> 			//required by getaddrinfo() and special constants
  	#include <stdlib.h>
  	#include <stdio.h>
  	#include <iostream>
	#include <random>    			// to create random nonce value
	#include <vector>
  	#define WSVERS MAKEWORD(2,2)
  	WSADATA wsadata; //Create a WSADATA object called wsadata. 
#endif

using namespace std;

// Global variables for important key values
long long eServer, nServer;	// for the server's public keys
long long eCA, nCA;			// for the CA keys
long long nonce;


//*******************************************************************
// FUNCTIONS
//*******************************************************************
void printBuffer(const char *header, char *buffer){
	std::cout << "------" << header << "------" << std::endl;
	for(unsigned int i=0; i < strlen(buffer); i++){
		if(buffer[i] == '\r'){
		   std::cout << "buffer[" << i << "]=\\r" << std::endl;	
		} else if(buffer[i] == '\n'){
		   std::cout << "buffer[" << i << "]=\\n" << std::endl;	
		} else {   
		   std::cout << "buffer[" << i << "]=" << buffer[i] << std::endl;
		}
	}
	std::cout << "---" << std::endl;
}


// Function to encrypt and decrypt 
long long repeatSquare(long long x, long long e, long long n) {
	long long y = 1;
	while(e > 0) {
		if((e % 2) == 0) {
			x = (x * x) % n;
			e = e / 2;
		} else {
			y = (x * y) % n;
			e = e - 1;
		}
	}
	return y;
}


// Create a random value for nonce which has to be less than 'nServer'
long long get_nonce() {
	random_device rd;                  
   	default_random_engine gen(rd());   
	long long num;

   	// generate and return a random nonce value. Smaller range than server's n value.
   	uniform_int_distribution<> distribution(1000, 5000);
	num = distribution(gen);
	return num;
}


// The Cipher Block Chain + RSA.  Encrypt a character from the users input.
long long cbc_encrypt(const char& c) {
    
	// get the ASCII value of the char
	int ascii = static_cast<int>(c);
    
	// XOR the ASCII with nonce, and ecnrypt the result
	long long result = static_cast<long long>(ascii) ^ nonce;
    long long encrypt_char = repeatSquare(result, eServer, nServer);
    
    nonce = encrypt_char;		// update the value for the nonce

    return encrypt_char;
}



//*******************************************************************
//  MAIN
//*******************************************************************
int main(int argc, char *argv[]) {
	printf("\n==================== <<< SECURE TCP SERVER >>> ====================\n");
	printf("==================== <<< Myles Stubbs >>> ====================\n\n");

	// Initialisation of variables 

	#if defined __unix__ || defined __APPLE__
		int s;
	#elif defined _WIN32
		SOCKET s;
	#endif

	#define BUFFER_SIZE 200 	// has to be at least big enough to receive the answer from the server
	#define SEGMENT_SIZE 70		// if fgets gets more than this number of bytes it segments the message

	char portNum[12];
	char send_buffer[BUFFER_SIZE], receive_buffer[BUFFER_SIZE];
	int n, bytes, count;
	
   	char serverHost[NI_MAXHOST]; 
   	char serverService[NI_MAXSERV];

	// Check WSAStartup and WinSock DLL version
	#if defined __unix__ || defined __APPLE__
		//nothing to do here
	#elif defined _WIN32
		int err;
		err = WSAStartup(WSVERS, &wsadata);
		if (err != 0) {
			WSACleanup();
			printf("WSAStartup failed with error: %d\n", err);
			exit(1);
		}
	
		if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
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

	memset(&hints, 0, sizeof(struct addrinfo));

	if(USE_IPV6){
		hints.ai_family = AF_INET6;  
	} else { 
		hints.ai_family = AF_INET;
	}

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	

	//*******************************************************************
	//	Dealing with user's arguments
	//*******************************************************************
 
	// Print the connection details based on if given an IP or using defaults
   	if (argc == 3){ 
	    sprintf(portNum,"%s", argv[2]);
	    printf("\nUsing port: %s \n", portNum);
	    iResult = getaddrinfo(argv[1], portNum, &hints, &result);
	} else {
	    printf("USAGE: Client IP-address [port]\n"); //missing IP address
		sprintf(portNum,"%s", DEFAULT_PORT);
		printf("Default portNum = %s\n", portNum);
		printf("Using default settings, IP:127.0.0.1, Port:1234\n");
		iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	}
	
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		#if defined _WIN32
        	WSACleanup();
		#endif  
		return 1;
   	}	 
		

	//*******************************************************************
	// CREATE CLIENT'S SOCKET 
	//*******************************************************************
	#if defined __unix__ || defined __APPLE__
		s = -1;
	#elif defined _WIN32
		s = INVALID_SOCKET;
	#endif

	s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	
	//check for errors in socket allocation
	#if defined __unix__ || defined __APPLE__
		if (s < 0) {
			printf("socket failed\n");
			freeaddrinfo(result);
		}
	#elif defined _WIN32
		if (s == INVALID_SOCKET) {
			printf("Error at socket(): %d\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			exit(1);//return 1;
		}
	#endif


	//*******************************************************************
	// CONNECT
	//*******************************************************************
	if (connect(s, result->ai_addr, result->ai_addrlen) != 0) {
		printf("\nconnect failed\n");
		freeaddrinfo(result);
		
		#if defined _WIN32
			WSACleanup();
		#endif 	
		exit(1);
	} 
	
	// if connect is successful
	else {
		char ipver[80];
		
		// Get IP version
		if (result->ai_family == AF_INET) {
			strcpy(ipver,"IPv4");
		} else if(result->ai_family == AF_INET6){
			strcpy(ipver,"IPv6");
		}


		#if defined __unix__ || defined __APPLE__     
			int returnValue;
		#elif defined _WIN32      
			DWORD returnValue;
		#endif

		memset(serverHost, 0, sizeof(serverHost));
	    memset(serverService, 0, sizeof(serverService));

        returnValue=getnameinfo((struct sockaddr *)result->ai_addr,  result->ai_addrlen,
               serverHost, sizeof(serverHost),
               serverService, sizeof(serverService), NI_NUMERICHOST);

		if(returnValue != 0){
			#if defined __unix__ || defined __APPLE__     
				printf("\nError detected: getnameinfo() failed with error\n");
			#elif defined _WIN32      
				printf("\nError detected: getnameinfo() failed with error#%d\n",WSAGetLastError());
			#endif       
	       exit(1);

	    } else{
		   printf("\nConnected to <<<SERVER>>> extracted IP address: %s, %s at port: %s\n\n", serverHost, ipver, portNum);  
	    }
	} // end of successful connect setup
	

	printf("\n******************************  SENDING NONCE AND RECEIVING KEYS  ******************************\n\n");

	
	//*******************************************************************
	// RECEIVING SERVER'S KEYS, AND SENDING NONCE
	//*******************************************************************
	memset(&receive_buffer, 0, BUFFER_SIZE);
	long long e_encryp, n_encryp;				// holds server's ENCRYPTED public key values
	
	// This loop will run until the client has sent its Nonce, and received the servers ACK
	while(true) {
		
		int i = 0;
		while(1) {			
			bytes = recv(s, &receive_buffer[i], 1, 0);
			
			// Check message is received correctly
			if(bytes <= 0) {
				printf("receiving keys has failed");
				#if defined _WIN32
					WSACleanup();
				#endif
				exit(1);
			}

			if (receive_buffer[i] == '\n') {  /*end on a LF*/
	            receive_buffer[i] = '\0';
	            break;
			}
			if (receive_buffer[i] != '\r') i++;   /*ignore CR's*/
		
		} // end of receiving the message


		//Receive the CA key values from the server. These are NOT encrypted, this is just so the client gets the values required
		if(strncmp(receive_buffer, "CA", 2) == 0) {
			
			// Check if successfully extracted the values for the keys
			int scannedIems = sscanf(receive_buffer, "CA %lld %lld", &eCA, &nCA);
			if(scannedIems != 2) {
				printf("ERROR:  retireval of CA keys was unsuccessful. Exiting.\n");
				exit(1);
			} else {
				printf("Successfully received the public Certificate Auhtority key:   eCA = %lld  nCA = %lld\n", eCA, nCA);
			}
		}


		// Used to get the ENCRYPTED server's public keys, decrypt them, then send ACK to server.
		if(strncmp(receive_buffer, "PUBLIC_KEY", 10) == 0) {
			
			// Try extract the server's encrypted public key values from the server
			int scannedItems = sscanf(receive_buffer, "PUBLIC_KEY %lld %lld", &e_encryp, &n_encryp);
			long long encrypted_nonce;
			
			if(scannedItems != 2) {
				printf("ERROR:  retireval of Public Keys was unsuccessful. Exiting.\n");
				exit(1);
			} else {
				printf("\nSuccessfully received server's encrypted Public Key:   PUBLIC_KEY %lld,  %lld\n", e_encryp, n_encryp);

				// Decrypt the keys using the CA values
				eServer = repeatSquare(e_encryp, eCA, nCA);
				nServer = repeatSquare(n_encryp, eCA, nCA);
				printf("The decrypted server's Public Key:  (%lld,  %lld)\n", eServer, nServer);	 
				
				// Send an ACK to the server when received the public key
				printf("----> Sending acknowledgement to the server:	ACK 226 (Public key received)\n");
				sprintf(send_buffer, "ACK 226\n");
				bytes = send(s, send_buffer, strlen(send_buffer), 0);

				// Generate a random Nonce. This value will be less that the server's n value.
				nonce = get_nonce();
				printf("\nThe plaintext/original nonce =   %lld\n", nonce);

				// encrypt the nonce using the decrypted server's public key
				encrypted_nonce = repeatSquare(nonce, eServer, nServer);
				printf("----> Sending the encrypted nonce =   %lld\n", encrypted_nonce);

				// send the encrypted nonce
				count = snprintf(send_buffer, BUFFER_SIZE, "NONCE %lld\n", encrypted_nonce);	
				if(count >= 0 && count < BUFFER_SIZE) {
					bytes = send(s, send_buffer, strlen(send_buffer), 0);
				} else {
					printf("ERROR:  the encrypted nonce failed to send. Exiting.");
					exit(1);
				}
			}
		}

		// Used to receive the ACK from server for the nonce value
		if(strncmp(receive_buffer, "ACK", 3) == 0) {
            int ack_value;                               // store the ACK code
            int scannedItems = sscanf(receive_buffer, "ACK %d", &ack_value);
            
            if(scannedItems == 1 && ack_value == 220) {
               printf("Received ACK from server: ACK 220;  Nonce ok.\n");
			   memset(&receive_buffer, 0, BUFFER_SIZE);
			   break;									
            } else {
               printf("ERROR:   failed to receive a positive ACK from the server\n");
			   break;
            }
         }
	}
	


	//*******************************************************************
	// GET INITIAL USERS INPUT. PROCESS UNLESS A '.' IS ENTERED.
	//*******************************************************************
	printf("\n\n----------------------------------------------------------------------\n");
	printf("You may now start sending encrypted messages to the <<< SERVER >>>\n");
	printf("\nType here:  ");
	
	// Using a new buffer to store the input instead of the send_buffer.
	char input_buffer[BUFFER_SIZE];
	memset(&input_buffer, 0, BUFFER_SIZE);						
    if(fgets(input_buffer, SEGMENT_SIZE, stdin) == NULL){
		printf("error using fgets()\n");
		exit(1);
	}
    

	//*******************************************************************
	//SEND MESSAGE TO SERVER
	//*******************************************************************

	string encrypted_message = "";
	string plain_text = "";
	while ((strncmp(input_buffer, ".", 1) != 0)) {
		
		// Tokenise the input using 'space' as a delimeter. Then process each char of each token
		char *token = strtok(input_buffer, " ");		
		
		while(token != NULL){
			for(size_t i = 0; i < strlen(token); ++i) {
				long long encrypted_char = cbc_encrypt(token[i]);	// encrypt one char at a time
				printf("\nOriginal character was  [%c].\nThe encrypted char is  [%lld]\n", token[i], encrypted_char);

				// build up the encrypted message
				encrypted_message += to_string(encrypted_char);

				// send each encrypted char to the server
				count = snprintf(send_buffer, BUFFER_SIZE, "%lld\n", encrypted_char);
				if(count >= 0 && count < BUFFER_SIZE) {
					bytes = send(s, send_buffer, strlen(send_buffer), 0);
					printf("----> Sending the encrypted char: %s\n",send_buffer);
				} else {
					printf("ERROR:  failed to send the current encrypted char. Exiting.\n");
					break;
				}	
	
			}
			
			plain_text += token;
			

			// get the next token
			token = strtok(NULL, " ");
			
			// if there is another token, then send an encrypted space char
			if(token != NULL) {
				int space_ascii = static_cast<int>(' ');
				long long result = static_cast<long long>(space_ascii) ^ nonce;
				long long encrypted_space = repeatSquare(result, eServer, nServer);
				nonce = encrypted_space;

				plain_text += " ";
				encrypted_message += to_string(encrypted_space);

				// send the encrypted space
				count = snprintf(send_buffer, BUFFER_SIZE, "%lld\n", encrypted_space);
				if(count >= 0 && count < BUFFER_SIZE) {
					bytes = send(s, send_buffer, strlen(send_buffer), 0);
					printf("\n----> Sending the encrypted space: %s\n",send_buffer);
				} else {
					printf("ERROR:  failed to send the encypted space. Exiting.\n");
					break;
				}	
			}
		} // end of input

		// send the delimeter of '\r\n' so the server knows is the end of this message
		sprintf(send_buffer, "\r\n");
		bytes = send(s, send_buffer, strlen(send_buffer), 0);
		if(bytes < 0) {
			printf("ERROR:  delimeter failed to send. Exiting.\n");
			break;
		} else {
			printf("\n----> Sending the plaintext delimeter\n\n");
		}
		
		const char *encrypted_str = encrypted_message.c_str();
		const char *plain_str = plain_text.c_str();
		printf("\nThe plain text message was:   %s\n", plain_str);
		printf("The fully encrypted message is:   %s\n", encrypted_str);

		// reset the strings 
		encrypted_message = "";		
		plain_text = "";


		//*******************************************************************
		// GET NEW INPUT FROM USER  -> NO RESPONSE FROM SERVER
		//*******************************************************************

		memset(&input_buffer, 0, BUFFER_SIZE);	
		printf("\nType here:  ");
		if(fgets(input_buffer,SEGMENT_SIZE,stdin) == NULL){
			printf("error using fgets()\n");
			exit(1);
		}
	     
		
	}  // end of checking users input for a '.'
	
	printf("\n--------------------------------------------\n");
	printf("<<<CLIENT>>> is shutting down...\n");

	//*******************************************************************
	//CLOSESOCKET   
	//*******************************************************************
	#if defined __unix__ || defined __APPLE__
		close(s);			//close listening socket
	#elif defined _WIN32
		closesocket(s);		//close listening socket
		WSACleanup(); 		//call WSACleanup when done using the Winsock dll
	#endif


   return 0;
}

