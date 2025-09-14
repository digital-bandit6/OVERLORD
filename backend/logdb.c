#include "common.h"
#include "logdb.h"
#include "fileio.h"

const char *event(Log_status_code code,Log_severity severity){
        const char *message = log_message(code);
        const char *sev = log_severity(severity);
        char stamp[20];

        FILE *file = open_and_check_file(LOGDB,APPEND);
        if(!file){
                file = open_and_check_file(LOGDB,WRITE);
        }
	timestamp(stamp,sizeof(stamp),LOG);
	fprintf(file,"%s %s\n",sev,message);
	fclose(file);

}

const char *log_message(Log_status_code code){
	switch(code){
		case OPEN_FILE:
			return "Opened File";
		case CLOSE_FILE:
			return "Closed File";
		case MEMORY_ALLOCATION:
			return "Memory Allocation";
		case MEMORY_FREE:
			return "Memory Freed";
		case FIREWALL_CREATION:
			return "Firewall Created";
		case FIREWALL_DELETION:
			return "Firewall Deleted";
		case FIREWALL_SEARCH:
			return "Firewall Found";
		default:
			return "Unkown Code!";

	}
}
const char *log_severity(Log_severity severity){
	switch(severity){
		case SUCCESS:
			return "[ SUCCESS ] ";
		case INFO:
			return "[ INFO ]";
		case ERROR:
			return "[ ERROR ]";
		default:
			return "[ UNKNOWN SEVERITY! ]";
	}
}



