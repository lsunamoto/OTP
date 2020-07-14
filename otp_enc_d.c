#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead = 0;
	socklen_t sizeOfClientInfo;
	char buffer[150000];//holds the client's message
	char *verify;//token that indicates encryption/decryption
	char *bufferM;//token that holds client's message
	char *bufferK;//token for key
	int messEnc[150000]; //array to hold message converted to ints
	int keyEnc[150000];//holds key chars converted to ints
	int sumEnc[150000];//array holds message+key ints
	int ciphEnc[150000];//array to hold modulo ints
	memset(messEnc,'\0',150000);
	memset(keyEnc,'\0',150000);
	char encryptionMess[150000];//holds the encryption of the message using a key
	memset(encryptionMess,'\0',150000);
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"otp_enc_d:USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("otp_enc_d ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("otp_enc_d ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	while(1){ 
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("otp_enc_d ERROR on accept");

		//Child will handle all communication with client from this point onward------------
		int childExitMethod = -5;
		pid_t childPid = -5;
		childPid = fork();
		if(childPid == -1){ 
				printf("failed forking child");
				fflush(stdout);
				exit(1);
		}else if(childPid == 0){ 
			// Get the message from the client and display it
			memset(buffer, '\0', sizeof(buffer));
		
			//Handshake: verify connection is encryption
			char indicator[20];//d(decryption) or e(encryption)
			memset(indicator,'\0',sizeof(indicator));
			recv(establishedConnectionFD,indicator,sizeof(indicator),0);
			//check if received d/e
			if(indicator[0] != 101){ 
		   		//reject client(tell them to exit with # delim.) and terminate 
				int totChar = 0;//#characters written
				char errMess[150000];//contains chars that indicate to otp_enc they are not authorized to communicate
				memset(errMess,'\0',150000);
				strcpy(errMess,"###");
				while(totChar<strlen(errMess)){ 
					charsRead = send(establishedConnectionFD,errMess,sizeof(errMess),0);//send cipher text back to client
					totChar += charsRead;
				}
		   	
			   	exit(0);//on child process
			}
		
			//otp_enc authenticated,receive message and key
			send(establishedConnectionFD,indicator,strlen(indicator),0);
			//receive until last delimiter found in small chunks
			char readBuffer[1000];//smaller buffer required to receive small chunks from otp_enc
			charsRead = 0;
			while(strstr(buffer,"$") == NULL){ 
				memset(readBuffer,'\0',sizeof(readBuffer));
				charsRead = recv(establishedConnectionFD, readBuffer, sizeof(readBuffer)-1, 0); // Read the client's message from the socket
				strcat(buffer,readBuffer);
			}

			//Tokenize message into plain text & key & store their lengths
			const char s[2] = "@";
			//const char t[2] = "$";
			bufferM = strtok(buffer,s);
			bufferK = strtok(NULL,s);
			int messLen = strlen(bufferM);
			int keyLen = strlen(bufferK);
		
			//memset buffers with null terminators for encryption
			memset(messEnc,'\0',150000);
			memset(keyEnc,'\0',150000);
			memset(encryptionMess,'\0',150000);
			memset(sumEnc,'\0',150000);
			memset(ciphEnc,'\0',150000);
			//ENCRYPTION
			int i;
			//convert message/text to corresponding ints (spaces are 26)
			for (i=0;i<messLen;i++){ 
				messEnc[i-1] = (bufferM[i]-65);
				//handle spaces
				if(messEnc[i-1]<0){ 
					messEnc[i-1]=26;
				}
			}
			//convert key to corresponding ints
			for (i=0;i<keyLen;i++){ 
				keyEnc[i-1] = (bufferK[i]-65);
				//handle spaces
				if(keyEnc[i-1]<0){ 
					keyEnc[i-1]=26;
				}
			}
			//sum up each position of each array
			for(i=0;i<messLen;i++){ 
				sumEnc[i] = (messEnc[i-1]+keyEnc[i-1]);
			}
			//find modulo 27 for each position
			for(i=0;i<messLen;i++){ 
				ciphEnc[i]= sumEnc[i] % 27;	
			}

			//convert cipher ints to letters
			for(i=0;i<messLen;i++){ 
				if(ciphEnc[i] == 26){ 
					encryptionMess[i] = ' ';
				}else{ 
					encryptionMess[i] = ciphEnc[i]+65;
				}
			}

			//make sure all of the encrypted message is sent to client
			int totChar = 0;//#characters written
			charsRead = 0;
			while(totChar<strlen(encryptionMess)){ 
				charsRead = send(establishedConnectionFD,encryptionMess,sizeof(encryptionMess),0);//send cipher text back to client
				totChar += charsRead;
			}
		
			if (charsRead < 0) error("ERROR writing to socket");
		
			exit(0);
		}else{ 
			//parent
			waitpid(childPid,&childExitMethod,0);//block parent until child w/ specified PID terminates
		}
		close(establishedConnectionFD); // Close the existing socket which is connected to the client
	}
	close(listenSocketFD); // Close the listening socket
	return 0; 
}
