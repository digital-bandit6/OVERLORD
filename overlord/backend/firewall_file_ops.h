#ifndef FIREWALL_FILE_OPS_H
#define FIREWALL_FILE_OPS_H

#define MAXSIZE 250
typedef struct Firewall{
        char domain[MAXSIZE];
        char device_type[MAXSIZE];
        char device_platform[MAXSIZE];
        char serial_number[MAXSIZE];
        char current_version[MAXSIZE];
        char hostname[MAXSIZE];
        char ha_state[MAXSIZE];
        char vip[MAXSIZE];
        char selfip[MAXSIZE];
        char manager[MAXSIZE];
        char manager_adom[MAXSIZE];
        char analyzer[MAXSIZE];
        char analyzer_adom[MAXSIZE];
        char console_server[MAXSIZE];
        char console_tty[MAXSIZE];
	struct Firewall *next;
}Firewall;


int load_csv_into_memory(Firewall **head);
void convert_to_lower(char *input);
struct Firewall *allocate_memory(void);
Firewall *create_entry(void);
int write_entry_to_file(Firewall *fw);
int delete_entry_from_file(Firewall **head);
void print_all_entries(Firewall *head);
void free_memory(Firewall *head);
int search_entry(Firewall *head);



#endif
