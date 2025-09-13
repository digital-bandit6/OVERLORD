#ifndef LOGDB_H
#define LOGDB_H

#define LOGDB "events.log"

//STATUS CODES FOR EVENTS
typedef enum{
	OPEN_FILE,
	CLOSE_FILE,
	MEMORY_ALLOCATION,
	MEMORY_FREE,
	FIREWALL_CREATION,
	FIREWALL_DELETION,
	FIREWALL_SEARCH,
}Log_status_code;

//EVENT SEVERITY
typedef enum{
	INFO,
	SUCCESS,
	ERROR,
}Log_severity;



const char *event(Log_status_code code,Log_severity severity);
const char *log_message(Log_status_code code);
const char *log_severity(Log_severity severity);


#endif
