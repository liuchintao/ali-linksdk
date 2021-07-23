#ifndef __BUFFER_MGR_H__
#define __BUFFER_MGR_H__

typedef struct RA_BUFFER_INFO
{
    char* buffer;
    int   size;          //buffer的大小
    int   read_index;     //读位置下标
    int   write_index;    //写位置下标
}RA_BUFFER_INFO_S;

int create_ra_buffer(RA_BUFFER_INFO_S *RAbuffer, int size);
void release_ra_buffer(RA_BUFFER_INFO_S* buffer);
int reset_ra_buffer(RA_BUFFER_INFO_S* buffer);
int write_ra_buffer(RA_BUFFER_INFO_S* buffer, const char*data, int len);
char* get_ra_buffer_read_pointer(RA_BUFFER_INFO_S* buffer);
char* get_ra_buffer_write_pointer(RA_BUFFER_INFO_S* buffer);
int get_ra_buffer_read_len(RA_BUFFER_INFO_S* buffer);
int move_ra_buffer_read_pointer(RA_BUFFER_INFO_S* buffer, int offset_len);
int move_ra_buffer_write_pointer(RA_BUFFER_INFO_S* buffer, int offset_len);
int memmove_ra_buffer(RA_BUFFER_INFO_S* buffer, int offset_len);
void reset_ra_buffer_read_point(RA_BUFFER_INFO_S* buffer);
void reset_ra_buffer_write_point(RA_BUFFER_INFO_S* buffer);
int join_content_before_ra_buffer(char*data, int len, RA_BUFFER_INFO_S *channel_buffer);

#endif
