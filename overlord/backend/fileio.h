#ifndef FILEIO_H
#define FILEIO_H


typedef enum{READ,WRITE,APPEND}File_mode;
typedef enum{LOG,BACKUP}Timestamp_mode;

FILE *open_and_check_file(const char *file, File_mode mode);
const char *timestamp(char *time_str,size_t size,Timestamp_mode type);



#endif
