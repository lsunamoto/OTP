#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#define MAXBUFFLEN 150000


void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[MAXBUFFLEN];//largest ciphertext file is 70,000
	char buffer2[MAXBUFFLEN];//contains key
	char indicator[5];//contains d that indicates decryption and @ separator
	memset(indicator,'\0',strlen(indicator));
	strcpy(indicator,"d");

    	//argument count should be at least 4: otp_enc myplaintext mykey port#	
	if (argc < 4) { fprintf(stderr,"USAGE: %s hostname port\n", argv[0]); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	//port number coord. w/ argv[3]
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	//do a dns lookup & return address info
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "otp_dec: ERROR, no such host\n"); exit(0); }
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("otp_dec: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("otp_dec: ERROR connecting");

	//Get plain text
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
	FILE * fp1;
	size_t newLen;
	fp1 = fopen(argv[1],"r");
	if(fp1 != NULL){ 
		newLen = fread(buffer, sizeof(char), MAXBUFFLEN, fp1);
		if(ferror(fp1) != 0){ 
			fputs("Error reading file",stderr);
		}
		fclose(fp1);
	}
	
	//check if the file contains any bad characters
	//terminate and send exit val of 1 to stderr if so
	int e;
	for(e=0;e<newLen-1;e++){ 
		//check each character (valid:ascii A-Z and 'space'(32))
		if((int)buffer[e] > 90 || (int)buffer[e] < 65 && (int)buffer[e] != 32){ 
			fprintf(stderr,"input contains bad characters\n");
			exit(1);
		}	
	}
	
	//Get key 
	memset(buffer2, '\0', sizeof(buffer2)); // Clear out the buffer array
	FILE * fp2;
	fp2 = fopen(argv[2],"r");
	if(fp2 != NULL){ 
		size_t newLen2 = fread(buffer2, sizeof(char), MAXBUFFLEN, fp2);
		if(ferror(fp2) != 0){ 
			fputs("Error reading file",stderr);
		}
		fclose(fp2);
	}
	
	//check if the key file is shorter than the plaintext
	//terminate and sent exit val 1 to stderr if so	
	if((strlen(buffer2)-1) < strlen(buffer)){ 
		fprintf(stderr,"keygen is too short\n");
	   	exit(1);
	}
	int totChar = strlen(buffer);//#char to receive from otp_dec_d
	buffer[strcspn(buffer, "\n")] = '@'; // Remove the trailing \n and replace w/ @ to separate plain text and key
	buffer2[strcspn(buffer2, "\n")] = '@'; // Remove the trailing \n and add delimeter
	
	//store plantext and keygen in final buffer to be sent
	strcat(buffer,buffer2);
	strcat(buffer,"$");//add delimitor 

	//send decryption char to otp_dec_d.c
	send(socketFD,indicator,strlen(indicator),0);
	recv(socketFD,indicator,sizeof(indicator),0);

	//check if otp_dec is authorized to communicate w/ port/"server"
	//35 is ascii # and is the char sent if not authorized
	if(strstr(indicator,"###") != NULL){ 
		//send error message, terminate, and exit val of 2 to stderr 
		fprintf(stderr, "otp_dec Error: could not contact otp_dec_d on port %s\n", argv[3]); 
		exit(2);
	}
	
	// Send message to otp_dec_d
	int accWritten = 0;//#char actually written
	while(accWritten<strlen(buffer)){ 
		charsWritten = send(socketFD, buffer, sizeof(buffer), 0); // Write to the server
		accWritten += charsWritten;
	}
	if (charsWritten < 0) error("otp_dec: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("otp_dec: WARNING: Not all data written to socket!\n");

	//check that all of the message is sent
	int checkSend = -5; //amt of bytes remaining in the send buffer 
	do{ 
		ioctl(socketFD,TIOCOUTQ,&checkSend);//check the send buffer for this socket
	}while(checkSend>0);//loop until send buffer is empty
	if(checkSend>0) error("ioctl error");//check if we actally stopped the loop b/c of an error
	
	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	//receive all characters in smaller chunks
	char readBuffer[1000];
	int actRead = 0;//char actually read
	while(actRead < totChar){
	  	memset(readBuffer,'\0',sizeof(readBuffer)); 
		charsRead = recv(socketFD, readBuffer, sizeof(readBuffer) - 1, 0); // Read data from the socket, leaving \0 at end
		strcat(buffer,readBuffer);
		actRead += charsRead;
	}
	
	if (charsRead < 0) error("otp_dec: ERROR reading from socket");
	printf("%s\n", buffer);
	close(socketFD); // Close the socket
	return 0;
}
