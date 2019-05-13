#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <netinet/tcp.h>

int http_length;
int print_warning_site(const unsigned char *data);

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id=0;
    struct nfqnl_msg_packet_hdr *ph;
    struct iphdr *ih;
    struct tcphdr *th;

    if((ph=nfq_get_msg_packet_hdr(nfa)))
        id = ntohl(ph->packet_id);

    nfq_get_payload(nfa,&data);

    ih = (struct iphdr *)data;

    if (ih->protocol==06) {
        printf("==============TCP Right==============\n");
        //printf("********%2X***********\n", ih->protocol);

        data += (ih->ihl*4);
        //printf("****************%d****************\n",ih->ihl*4);
        th = (struct tcphdr *)data;

        if (ntohs(th->th_dport)==80){
            printf("==========TCP PORT=80 RIGHT==========\n");
            //printf("*********%d**********\n", ntohs(th->th_dport));

            if (((ntohs(ih->tot_len))-(ih->ihl*4)-(th->th_off*4)) >= 0){
                printf("==========TCP DATA IS EXIST==========\n");
                //printf("**********%d**********\n",(th->th_off*4));

                data += (th->th_off*4);
                http_length = ((ntohs(ih->tot_len))-(ih->ihl*4)-(th->th_off*4));
                int host_res = print_warning_site(data);

                if (host_res==0){
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }

            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            //printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    //printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

int print_warning_site(const unsigned char *data){
    printf("\n==============HTTP DATA==============\n");
    //printf("*******%d*********",http_length);

    unsigned char *http_data;
    http_data=data;

    for(int i=0; i<=http_length; i++){
        printf("%c", http_data[i]);
    }
    printf("\n");

    char *temp = NULL;

    char a[] = { "Host:" };
    temp = strstr(http_data,a);
    //printf("*********%.*s**********\n", 21,temp);

    if (temp != NULL) {
        char b[] = { "test.gilgil.net" };
        temp = strstr(http_data,b);
        if (temp != NULL)
            printf("%s is Warning", b);

        printf("\n");

        return 0;
    }

    printf("\n");

    return 1;
}




