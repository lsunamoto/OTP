#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char *argv[]){ 
	int i,randNum, randChar;
	srand(time(NULL));//seed rand # generator
		
	//Create key by generated/printing one character at a time
	for(i=0;i<atoi(argv[1]);i++){ 
		randNum = rand() % 27;//generate rand# btwn 0 & 26
		if(randNum < 26){ 
			//# generated has corresponding ascii value to a char btwn A & Z
			randChar = 65 + randNum;//65 corresponds to A on ascii table
			printf("%c",randChar);	
			fflush(stdout);
		}else if(randNum == 26){ 
			//# generated corresponds to a space as default
			printf(" ");
			fflush(stdout);
		}
	}
	
	//add new line
	printf("\n");
	fflush(stdout);
	
	return 0;
}
