#include "common.h"
#include "logdb.h"
#include "user_input.h"
#include "fileio.h"
#include "firewall_file_ops.h"


void convert_to_lower(char input[]){
	unsigned int i = 0; 
	for(; input[i] != '\0' ; i++){
		if(input[i] >= 'A' && input[i] <= 'Z')
			input[i] = input[i] + ('a' - 'A');
		
	}
}
struct Firewall *allocate_memory(void){
	Firewall *fw = malloc(sizeof(Firewall));
	if(!fw){
		event(MEMORY_ALLOCATION,ERROR);
		return NULL;				
	}
	return fw;	
}
void free_memory(Firewall *head){
	Firewall *current = head;
	while(current){
		Firewall *next = current->next;
		free(current);
		current = next;
	}
}

int load_csv_into_memory(Firewall **head){
	FILE *file = open_and_check_file(FWDATA,READ);
	if(!file){
		event(OPEN_FILE,ERROR);
		return -1;
	}

	char buffer[4096];
	
	while(fgets(buffer,sizeof(buffer),file) != NULL){
		buffer[strcspn(buffer,"\n")] = '\0';
		char *fields[15];
		int field_index = 0;
		char *token = strtok(buffer,",");
		while(token != NULL && field_index < 15){
			fields[field_index++] = token;
			token = strtok(NULL,",");
		}
		if(field_index < 15) continue;

		Firewall *node = allocate_memory();
		if(!node){
			fclose(file);
			event(MEMORY_ALLOCATION,ERROR);
			return -1;
		}
		event(MEMORY_ALLOCATION,SUCCESS);
		char *firewall_fields[] = {
			node->domain,node->device_type,node->device_platform,
			node->serial_number,node->current_version,node->hostname,
			node->ha_state,node->vip,node->selfip,node->manager,
			node->manager_adom,node->analyzer,node->analyzer_adom,
			node->console_server,node->console_tty
		};
		size_t field_size[] = {
			sizeof(node->domain),sizeof(node->device_type),
			sizeof(node->device_platform),sizeof(node->serial_number),
			sizeof(node->current_version),sizeof(node->hostname),
			sizeof(node->ha_state),sizeof(node->vip),sizeof(node->selfip),
			sizeof(node->manager),sizeof(node->manager_adom),
			sizeof(node->analyzer),sizeof(node->analyzer_adom),
			sizeof(node->console_server),sizeof(node->console_tty)
		};


		for(int i = 0 ; i < field_index && i < 15 ; i++){
			strncpy(firewall_fields[i],fields[i],field_size[i] - 1);
			firewall_fields[i][field_size[i] - 1] = '\0';
		}
		node->next = NULL;
		if(*head == NULL){
			*head = node;
		}
		else{
			Firewall *current = *head;
			while(current->next)
				current = current->next;
			current->next = node;
		}
	}
	fclose(file);
	event(CLOSE_FILE,INFO);
	return 0;
}


Firewall *create_entry(void){
	Firewall *head = NULL;
	head = allocate_memory();
	if(!head){
		event(MEMORY_ALLOCATION,ERROR);
		return NULL;
	}
	get_user_input("Enter Firewall Domain: ",head->domain,sizeof(head->domain));
        get_user_input("Enter Firewall Device Type: ",head->device_type,sizeof(head->device_type));
        get_user_input("Enter Firewall Device Platform: ",head->device_platform,sizeof(head->device_platform));
        get_user_input("Enter Firewall Device Serial Number: ",head->serial_number,sizeof(head->serial_number));
        get_user_input("Enter Firewall Current Version: ",head->current_version,sizeof(head->current_version));
        get_user_input("Enter Firewall Hostname: ",head->hostname,sizeof(head->hostname));
        get_user_input("Enter Firewall HA State: ",head->ha_state,sizeof(head->ha_state));
        get_user_input("Enter Firewall VIP: ",head->vip,sizeof(head->vip));
        get_user_input("Enter Firewall SelfIP: ",head->selfip,sizeof(head->selfip));
        get_user_input("Enter Firewall Manager: ",head->manager,sizeof(head->manager));
        get_user_input("Enter Firewall Manager Adom: ",head->manager_adom,sizeof(head->manager_adom));
        get_user_input("Enter Firewall Analyzer: ",head->analyzer,sizeof(head->analyzer));
        get_user_input("Enter Firewall Analyzer Adom: ",head->analyzer_adom,sizeof(head->analyzer_adom));
        get_user_input("Enter Firewall Console Server: ",head->console_server,sizeof(head->console_server));
        get_user_input("Enter Firewall Console TTY: ",head->console_tty,sizeof(head->console_tty));
        
	head->next = NULL;
	
	return head;	
}

int write_entry_to_file(Firewall *fw){
	FILE *file = open_and_check_file(FWDATA,APPEND);
	if(!file){
		event(OPEN_FILE,ERROR);
		return -1;
	}
	
	fprintf(file,"%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			fw->domain,
			fw->device_type,
			fw->device_platform,
			fw->serial_number,
			fw->current_version,
			fw->hostname,
			fw->ha_state,
			fw->vip,
			fw->selfip,
			fw->manager,
			fw->manager_adom,
			fw->analyzer,
			fw->analyzer_adom,
			fw->console_server,
			fw->console_tty
	);
	fclose(file);
	event(CLOSE_FILE,INFO);
	free(fw);
	event(MEMORY_FREE,SUCCESS);
}

int delete_entry_from_file(Firewall **head){
	FILE *file = open_and_check_file(FWDATA,READ);
	FILE *temp = open_and_check_file("temp.csv",WRITE);
	if(!file || !temp){
		event(OPEN_FILE,ERROR);
		return -1;
	}
	char input[251];
	get_user_input("Enter Name Of Firewall to delete: ",input,sizeof(input));

	char buffer[4096];
	Firewall *prev = NULL;
	Firewall *current = *head;
	while(fgets(buffer,sizeof(buffer),file) != NULL){
		char buffer_copy[4096];
		strcpy(buffer_copy,buffer);
		char *fields[15];
		int field_index = 0;
		char *token = strtok(buffer_copy,",");
		while(token && field_index < 15){
			fields[field_index++] = token;
			token = strtok(NULL,",");
		}
		if(field_index > 5 && strcmp(fields[5], input) == 0){
			while(current){
				if(strcmp(current->hostname,input) == 0){
					printf("Entry Found\n");
					if(prev)
						prev->next = current->next;
					else
						*head = current->next;
					free(current);
					break;
				}
				prev = current;
				current = current->next;
			}
			continue;
		}
		
		fprintf(temp,"%s",buffer);
		if(buffer[strlen(buffer) -1] != '\n')
			fprintf(temp,"\n");
		
	}

	fclose(file);
	event(CLOSE_FILE,INFO);
	fclose(temp);
	event(CLOSE_FILE,INFO);
	remove(FWDATA);
	rename("temp.csv",FWDATA);
	return 0;
}


int search_entry(Firewall *head){
	char input[251];
	get_user_input("Enter Firewall Name to Search For: ",input,sizeof(input));

	Firewall *current = head;
	while(current){
		if(strcmp(current->hostname,input) == 0){
			printf("Domain: %s\nType: %s\nPlatform: %s\nSerial Number: %s\nCurrent Version: %s\nHostname: %s\nHA State: %s\nVIP: %s\nSelf IP: %s\nManager: %s\nManager Adom: %s\nAnalyzer: %s\nAnalyzer Adom: %s\nConsole Server: %s\nConsole TTY: %s\n------------------------------------------------------------\n",
			current->domain,current->device_type,current->device_platform,
			current->serial_number,current->current_version,current->hostname,
			current->ha_state,current->vip,current->selfip,current->manager,
			current->manager_adom,current->analyzer,current->analyzer_adom,
			current->console_server,current->console_tty);
			break;
		}
		current = current->next;
	}
	return -1;
}

void print_all_entries(Firewall *head){
	Firewall *current = head;
	

	while(current){
		printf("Domain: %s\nType: %s\nPlatform: %s\nSerial Number: %s\nCurrent Version: %s\nHostname: %s\nHA State: %s\nVIP: %s\nSelf IP: %s\nManager: %s\nManager Adom: %s\nAnalyzer: %s\nAnalyzer Adom: %s\nConsole Server: %s Console TTY: %s\n------------------------------------------------------------\n",
				current->domain,current->device_type,current->device_platform,
				current->serial_number,current->current_version,current->hostname,
				current->ha_state,current->vip,current->selfip,current->manager,
				current->manager_adom,current->analyzer,current->analyzer_adom,
				current->console_server,current->console_tty);
		current = current->next;
	}
	
	
}


