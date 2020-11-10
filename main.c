#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

FILE* in;

typedef struct hashtable
{   char s[50];
    int length;
    struct hashtable* hashNext;
}hashtable;

typedef struct site
{   char s[50];
    int length;
}site;

site block[1000000];

hashtable* h_table[100];

void AddHashData(int hash, hashtable* node) {
    if (h_table[hash] == NULL)
    {
        h_table[hash] = node;
    }
    else
    {
        node->hashNext = h_table[hash];
        h_table[hash] = node;
    }
}

int FindHashData(int hash, unsigned char* url) {
    if (h_table[hash] == NULL) {
        return 0;
    }
    if (memcmp(h_table[hash]->s, url, hash)==0)
    {
		printf("\n----------------\n");
		printf("block site\n%s",url);
		printf("----------------\n");	
        return 1;
    }
    else
    {
        hashtable* node = h_table[hash];
        while (node->hashNext)
        {
            if (memcmp(node->s, url, hash)==0)
            {
				printf("\n\n----------------\n");
				printf("block site\n%s",url);
				printf("----------------\n");				
                return 1;
            }
            node = node->hashNext;
        }
    }
    return  0;

}

int warning=0;
/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
	}

	mark = nfq_get_nfmark(tb);
	ifi = nfq_get_indev(tb);
	ifi = nfq_get_outdev(tb);
	ifi = nfq_get_physindev(tb);
	ifi = nfq_get_physoutdev(tb);
	ret = nfq_get_payload(tb, &data);
	ret = nfq_get_payload(tb, &data);

	if (ret >= 0){
		const char *get="GET";
		const char *da="\r\n";
		int i=0;
		int j=0;
		printf("\nwarning : %d\n",warning);
		warning=0;

		printf("payload_len=%d ", ret);
		//printf("%02x\n",(data[0]&0x1f)<<2);
		//dump(data,ret);
		data=&data[(data[0]&0x1f)<<2];//ip header length move
		//printf("\n%02x\n",(data[12]&0xf0)>>2);
		data=&data[((data[12]&0xf0)>>4)<<2];//tcp header length move
		const char *head = "Host: ";

		if(memcmp(get,data,3)==0)//get http check
			{
				//dump(data,20);
				while(memcmp(da,data+i,2)!=0){//get length check
					i++;
				}
				i=i+2;//i=get length
				data=&data[i];
				while(memcmp(da,data+j,2)!=0){//host length check
					j++;
				}
				j=j-6;//j=host length

				if(memcmp(data,head,6)==0){
					unsigned char host[50]={0, };

					//printf("\n\n%d\n\n",j);					
					data=&data[6];
					memcpy(host,data,j+2);//if host=gilgil warning=1;	
					//dump(host,j+2);			
					warning=FindHashData(j, host);			
					//printf("\n%d\n",warning);		
				}
			}
	}
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(warning==0){//if warning=1 accept
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else{//if warning=1 (host=gilgil) drop
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    in = fopen(argv[1], "r");
	if(in==NULL){
		return 0;
	}
    int i = 0;
    int hash = 0;
	int k=0;
	char* urlsite[1000000];
	static char* ptr[1000000];


    while (fgets(block[i].s,sizeof(block[i].s),in)!=NULL)
    {   

        hashtable* node = (hashtable*)malloc(sizeof(hashtable));
		sscanf(block[i].s,"%d,%s",&k,node->s);
		//printf("%s\n",node->s);
        node->length = strlen(node->s);
		//printf("%s %d\n",node->s, node->length);
        AddHashData(node->length, node);
        i++;
    }
	printf("\n\n%s\n\n",h_table[15]->s);
	printf("\n\n%s\n\n",h_table[15]->hashNext->s);

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
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
