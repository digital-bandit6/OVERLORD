#include "common.h"
#include "user_input.h"


void get_user_input(const char *prompt,char *input,size_t size){
	printf("%s ",prompt);
	if(fgets(input,size,stdin)){
		input[strcspn(input,"\n")] = '\0';
	}
	else{
		input[0] = '\0';
	}
	
}

