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
	char *bufferM;//token that holds ciphertext
	char *bufferK;//token for key
	int messDec[150000]; //array to hold message converted to ints
	int keyDec[150000];//holds key chars converted to ints
	int diffDec[150000];//array holds cipher-key ints
	int ciphDec[150000];//array to hold modulo ints
	memset(messDec,'\0',150000);
	memset(keyDec,'\0',150000);
	char decryptionMess[150000];//holds the decryption of the message using a key
	memset(decryptionMess,'\0',150000);
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"otp_dec_d:USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("otp_dec_d ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("otp_dec_d ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	while(1){ 
	// Accept a connection, blocking if one is not available until one connects
	sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client/otp_dec that will connect
	establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
	if (establishedConnectionFD < 0) error("otp_dec_d ERROR on accept");

	//Child will handle all communication with client from this point onward------------
	int childExitMethod = -5;
	pid_t childPid = -5;
	childPid = fork();
	if(childPid == -1){ 
			printf("failed forking child");
			fflush(stdout);
			exit(1);
	}else if(childPid == 0){ 
		memset(buffer, '\0', sizeof(buffer));

		//get the message that verifies communication is w/ otp_dec
		char indicator[20];//d(decryption) or e (encryption)
		memset(indicator,'\0',sizeof(indicator));
		recv(establishedConnectionFD,indicator,sizeof(indicator),0);

		//if (charsRead < 0) error("otp_dec_d ERROR reading from socket");
		if(indicator[0] != 100){ 
		   	//reject client(tell them to exit with # delim.) and terminate 
			int totChar = 0;//#characters written
			char errMess[150000];//contains chars that indicate to otp_dec they are not authorized to communicate
			memset(errMess,'\0',150000);
			strcpy(errMess,"###");
			while(totChar<strlen(errMess)){ 
				charsRead = send(establishedConnectionFD,errMess,strlen(errMess),0);//send reject message 
				totChar += charsRead;
			}
		   	
		   	exit(0);//on child process
		}
		
		// Send verification message back to otp_dec
		// Get the message from the client/otp_dec and display it
		send(establishedConnectionFD,indicator,strlen(indicator),0);
		//receive all characters until delimitor found in smaller chunks
		char readBuffer[1000];
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
		
		//memset buffers with null terminators for decryption
		memset(messDec,'\0',150000);
		memset(keyDec,'\0',150000);
		memset(decryptionMess,'\0',150000);
		memset(diffDec,'\0',150000);
		memset(ciphDec,'\0',150000);
		//DECRYPTION
		int i;
		//convert message/text to corresponding ints (spaces are 26)
		for (i=0;i<messLen;i++){ 
			messDec[i-1] = (bufferM[i]-65);
			//handle spaces
			if(messDec[i-1]<0){ 
				messDec[i-1]=26;
			}
		}
		//convert key to corresponding ints
		for (i=0;i<keyLen;i++){ 
			keyDec[i-1] = (bufferK[i]-65);
			//handle spaces
			if(keyDec[i-1]<0){ 
				keyDec[i-1]=26;
			}
		}
		//get difference for each position of each array
		//messDec is the ciphertext
		for(i=0;i<messLen;i++){ 
			diffDec[i] = (messDec[i-1]-keyDec[i-1]);
		}
		//find modulo 27 for each position
		for(i=0;i<messLen;i++){ 
			ciphDec[i]= diffDec[i] % 27;	
		}

		//convert cipher ints to letters
		for(i=0;i<messLen;i++){ 
			if(ciphDec[i] == -1){ 
				decryptionMess[i] = ' ';
			}else if(ciphDec[i]<0){ 
			       	ciphDec[i] = ciphDec[i] + 27;//handle negative modulo results
			   	ciphDec[i] = ciphDec[i] % 27;
				decryptionMess[i]=ciphDec[i]+65;	
			}else if(ciphDec[i] == 26){ 
				decryptionMess[i] = ' ';
			}else{ 
				decryptionMess[i] = ciphDec[i]+65;
			}
		}

		//make sure all of the decrypted message is sent to client
		int totChar = 0;//#characters written
		charsRead = 0;
		while(totChar<strlen(decryptionMess)){ 
			charsRead = send(establishedConnectionFD,decryptionMess,sizeof(decryptionMess),0);//send cipher text back to client
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
