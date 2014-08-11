#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/time.h> /* timeval */

#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQ_NUM 1
#define QUEUE_MAXLEN 4096

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}

static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *nfa, void *data) {
    printf("entering callback\n");
    int id = print_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int nfq_demo(void) {
    struct nfq_handle *h = nfq_open();
    if (!h) {
        return -1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("nfq_unbind_pf failed\n");
        return -1;
    }

    if (nfq_unbind_pf(h, AF_INET6) < 0) {
        printf("nfq_unbind_pf failed\n");
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("nfq_bind_pf failed\n");
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET6) < 0) {
        printf("nfq_bind_pf failed\n");
        return -1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, NFQ_NUM, nfq_cb, NULL);
    if (!qh) {
        printf("nfq_create_queue failed\n");
        return -1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
        return -1;

    if (nfq_set_queue_maxlen(qh, QUEUE_MAXLEN) < 0)
        return -1;

    nfnl_rcvbufsiz(nfq_nfnlh(h), QUEUE_MAXLEN * 1500);
    struct nfnl_handle *nh = nfq_nfnlh(h);
    int fd = nfnl_fd(nh);

#if 0
    int opt = 1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &opt, sizeof(int)) == -1)
        return -1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == -1)
        return -1;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
        return -1;
#endif
    
    char recv_buf[QUEUE_MAXLEN] __attribute__ ((aligned));
    while (1) {
        printf("waiting recv ...\n");
        int rv = recv(fd, recv_buf, QUEUE_MAXLEN, 0);
        if (rv < 0) {
            printf("recv %d bytes\n", rv);
        } else if (rv == 0) {
            printf("nothing recv\n");
        } else {
            printf("recv %d bytes\n", rv);
        }
        nfq_handle_packet(h, recv_buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);
}

int main() {
    nfq_demo();
    return 0;
}
