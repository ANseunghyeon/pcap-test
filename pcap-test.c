#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

//ip출력
void print_ip(const uint32_t ip_addr) { 
    const unsigned char *ip = (unsigned char*)&ip_addr; 
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]); 
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue; 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl << 2));
        
        // TCP 체크
        if(ip_hdr->ip_p != 6) continue;
        
		//이더넷 출력
        printf("=================\n");
        printf("Ethernet source: %02x:%02x:%02x:%02x:%02x:%02x, ",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("dest: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		
		// IP 출력
        printf("IP source: ");
        print_ip(ip_hdr->ip_src.s_addr);
        printf(", dest: ");
        print_ip(ip_hdr->ip_dst.s_addr);
        printf("\n");
        
		//TCP 출력
        const uint16_t src_port = htons(tcp_hdr->th_sport);
        const uint16_t dst_port = htons(tcp_hdr->th_dport);
        printf("TCP source port: %u, dest port: %u\n", src_port, dst_port);
        
		// data 출력
        printf("-----------------\n DATA: ");
        int data =  sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl + tcp_hdr->th_off)*4;
        for(int i = data; i < header->caplen && i <data + 20; i++) {
            printf("%02x ", packet[i]); 
        }
        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
