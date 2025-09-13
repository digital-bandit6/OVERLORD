#include "common.h"
#include "user_input.h"
#include "fileio.h"
#include "logdb.h"
#include "backup_and_restore.h"


int backup_data(void){
	char backup_file[150] = FWDATA;
	char time_stamp[20];

	FILE *file = open_and_check_file(FWDATA,READ);
	FILE *backup = open_and_check_file(backup_file,WRITE);
        if(!file && !backup){
		event(OPEN_FILE,ERROR);
        	return -1;
        }

        snprintf(backup_file,sizeof(backup_file),"%s_",FWDATA);
        timestamp(time_stamp,sizeof(time_stamp),BACKUP);
        strcat(backup_file,time_stamp);

        char buffer[4096];
        while(fgets(buffer,sizeof(buffer),file) != NULL){
                fputs(buffer,backup);
        }
        printf("Successfully Created Backup \n%s\n",backup_file);

        fclose(file);
        fclose(backup);
	event(CLOSE_FILE,INFO);
        return 0;

}
int restore_from_backup(void){
        char filename[1000];
        get_user_input("Enter FileName to restore From: ",filename,sizeof(filename));

        FILE *file = open_and_check_file(filename,READ);
        FILE *fdata = open_and_check_file(FWDATA,WRITE);
        if(!file || !fdata){
		event(OPEN_FILE,ERROR);
                return -1;
        }

	char buffer[4096];
        while(fgets(buffer,sizeof(buffer),file) != NULL){
        	fputs(buffer,fdata);
	}

        fclose(file);
        fclose(fdata);
	event(CLOSE_FILE,INFO);

        printf("Restore From File %s Successfully completed\n",filename);
        return 0;
}

