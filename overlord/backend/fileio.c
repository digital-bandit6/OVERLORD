#include "common.h"
#include "fileio.h"

FILE *open_and_check_file(const char *filename,File_mode mode){
        const char *file_mode;
        switch(mode){
                case WRITE: 
                        file_mode = "w"; break;
                case APPEND:
                        file_mode = "a"; break;
                case READ:
                        file_mode = "r"; break;
                default:
                        return NULL;

        }
        FILE *file = fopen(filename,file_mode);
        if(!file){
                printf("Error Opening File\n");
                return NULL;
        }
        return file;
}

const char *timestamp(char *time_str,size_t size,Timestamp_mode type){

        time_t t = time(NULL);
        struct tm *time_info = localtime(&t);

        switch(type){
                case LOG:
                        strftime(time_str,size,"%Y-%m-%d %H:%M:%S",time_info);
                        return time_str;

                case BACKUP:
                        strftime(time_str,size,"%Y-%m-%d",time_info);
                        return time_str;
        }
}
