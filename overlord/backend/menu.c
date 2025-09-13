#include "common.h"
#include "menu.h"
#include "user_input.h"
#include "fileio.h"
#include "logdb.h"
#include "firewall_file_ops.h"


void menu(void){
	char input[251];
	char buffer[4096];
	Firewall *head = NULL;
	if(load_csv_into_memory(&head) != 0){
		printf("Error loading Firewalls into memory!\n");
		return;
	}

	do{
		get_user_input("OverLord ~> ",input,sizeof(input));
		
		if(strcmp(input,"add") == 0){
			Firewall *fw = create_entry();
			write_entry_to_file(fw);
			free_memory(head);
			head = NULL;
			if(load_csv_into_memory(&head) == 0){
				printf("Entry Added Successfully\n");
				event(FIREWALL_CREATION,SUCCESS);
			}
		}
		else if(strcmp(input,"print") == 0){
			print_all_entries(head);
		}
		else if(strcmp(input,"delete") == 0){
			delete_entry_from_file(&head);
			if(load_csv_into_memory(&head) == 0){
				printf("Entry Deleted and reloaded Entries into Memory\n");
				event(FIREWALL_DELETION,SUCCESS);
			}
		}
		else if(strcmp(input,"search") == 0){
			search_entry(head);
		}
		if(strcmp(input,"help") == 0){
			printf("HELP MENU\n");
			printf("add new device -> add\n");
			printf("Print all devices -> print\n");
			printf("delete device -> delete\n");
			printf("search for a device -> search\n");
			
		}
	
	}while(strcmp(input,"exit") != 0);
	free_memory(head);
}
