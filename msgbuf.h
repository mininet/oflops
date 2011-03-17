#ifndef MSGBUF_H
#define MSGBUF_H

struct msgbuf
{
        char * buf;
            int len, start, end;
};


struct msgbuf *  msgbuf_new(int bufsize);
int              msgbuf_read(struct msgbuf * mbuf, int sock);
int              msgbuf_read_all(struct msgbuf * mbuf, int sock, int len);
int              msgbuf_write(struct msgbuf * mbuf, int sock, int len);
int              msgbuf_write_all(struct msgbuf * mbuf, int sock, int len);
void             msgbuf_grow(struct msgbuf *mbuf);
void             msgbuf_clear(struct msgbuf *mbuf);
void *           msgbuf_peek(struct msgbuf *mbuf);
int              msgbuf_pull(struct msgbuf *mbuf, char * buf, int count);
void             msgbuf_push(struct msgbuf *mbuf, char * buf, int count);
//int              msgbuf_count_buffered(struct msgbuf * mbuf);
#define msgbuf_count_buffered(mbuf) ((mbuf->end - mbuf->start))

#endif
