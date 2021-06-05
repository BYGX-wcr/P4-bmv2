#include <time.h>

typedef struct delay_pkt {
    int len;
    char* data;
    struct timespec ts;
} delay_pkt_t;

typedef struct delay_buffer {
    int size;
    delay_pkt_t* head;
} delay_buffer_t;

int insert_pkt(delay_buffer_t* buffer, delay_pkt_t* pkt);

int delete_head_pkt(delay_buffer_t* buffer);

delay_pkt_t* get_head(delay_buffer_t* buffer);

struct timespec get_head_ts(delay_buffer_t* buffer);

int time_cmp(struct timespec left, struct timespec right);