#include "header.h"
#include <signal.h>

#define MAX 10000

int flag = 0;

typedef struct
{
    struct pcap_pkthdr header;
    const u_char *data;
} storedpkt;

storedpkt *pktarray = NULL;
int pktcount = 0;

void hex_dump(const uint8_t *data, int len);

void show_summary() {
    printf("\n[C-Shark] Packet Summary:\n");
    for (int i = 0; i < pktcount; i++) {
        struct pcap_pkthdr *h = &pktarray[i].header;
        const u_char *p = pktarray[i].data;

        struct ether_header *eth = (struct ether_header *)p;
        uint16_t etype = ntohs(eth->ether_type);
        char *etype_str;
        switch (etype) {
            case 0x0800: etype_str = "IPv4"; break;
            case 0x86DD: etype_str = "IPv6"; break;
            case 0x0806: etype_str = "ARP"; break;
            default: etype_str = "Unknown"; break;
        }

        printf("Packet #%d | Timestamp: %ld.%06ld | Length: %u bytes | %s\n",
               i + 1,
               (long)h->ts.tv_sec, (long)h->ts.tv_usec,
               h->caplen, etype_str);
    }
}

void deep_inspect(int id) {
    struct pcap_pkthdr *h = &pktarray[id].header;
    const u_char *p = pktarray[id].data;
    struct ether_header *eth = (struct ether_header *)p;
    uint16_t etype = ntohs(eth->ether_type);

    printf("\n\n[C-Shark] In-Depth Packet Inspection for Packet #%d\n", id + 1);
    printf("Timestamp: %ld.%06ld | Length: %u bytes\n",
           (long)h->ts.tv_sec, (long)h->ts.tv_usec, h->caplen);
    printf("----------------------------------------------------------\n");

    
    printf("[Full Frame Hex Dump]\n");
    hex_dump(p, h->caplen);
    printf("----------------------------------------------------------\n");

    
    printf("[Ethernet Header]\n");
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("EtherType: 0x%04x\n\n", etype);

    const u_char *payload = p + sizeof(struct ether_header);

    
    if (etype == 0x0800) {
        struct iphdr *ip = (struct iphdr *)payload;
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        printf("[IPv4 Header]\n");
        printf("Version: %d | Header Length: %d bytes | Total Length: %d\n",
               ip->version, ip->ihl * 4, ntohs(ip->tot_len));
        printf("Identification: 0x%04x | TTL: %d | Protocol: %d\n",
               ntohs(ip->id), ip->ttl, ip->protocol);
        printf("Src IP: %s | Dst IP: %s\n", inet_ntoa(src), inet_ntoa(dst));
        printf("----------------------------------------------------------\n");

        
        if (ip->protocol == 6) {
            struct tcphdr *tcp = (struct tcphdr *)(payload + ip->ihl * 4);
            printf("[TCP Header]\n");
            printf("Src Port: %d | Dst Port: %d\n",
                   ntohs(tcp->source), ntohs(tcp->dest));
            printf("Seq: %u | Ack: %u\n", ntohl(tcp->seq), ntohl(tcp->ack_seq));
            printf("Flags: %s%s%s%s%s%s\n",
                   tcp->syn ? "SYN " : "", tcp->ack ? "ACK " : "",
                   tcp->fin ? "FIN " : "", tcp->psh ? "PSH " : "",
                   tcp->rst ? "RST " : "", tcp->urg ? "URG " : "");
            printf("----------------------------------------------------------\n");

            int ip_hlen = ip->ihl * 4;
            int tcp_hlen = tcp->doff * 4;
            int payload_len = ntohs(ip->tot_len) - ip_hlen - tcp_hlen;
            const uint8_t *pl = payload + ip_hlen + tcp_hlen;
            printf("[TCP Payload] (%d bytes)\n", payload_len);
            hex_dump(pl, payload_len < 64 ? payload_len : 64);
        } else if (ip->protocol == 17) {
            struct udphdr *udp = (struct udphdr *)(payload + ip->ihl * 4);
            printf("[UDP Header]\nSrc Port: %d | Dst Port: %d | Length: %d\n",
                   ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
            int ip_hlen = ip->ihl * 4;
            const uint8_t *pl = payload + ip_hlen + sizeof(struct udphdr);
            int payload_len = ntohs(ip->tot_len) - ip_hlen - sizeof(struct udphdr);
            printf("[UDP Payload] (%d bytes)\n", payload_len);
            hex_dump(pl, payload_len < 64 ? payload_len : 64);
        }
    } else if (etype == 0x0806) {
        struct arphdr *arp = (struct arphdr *)payload;
        printf("[ARP Header]\n");
        printf("Operation: %s (%d)\n", ntohs(arp->ar_op) == 1 ? "Request" : "Reply", ntohs(arp->ar_op));
        printf("Hardware Type: %d | Protocol: 0x%04x\n",
               ntohs(arp->ar_hrd), ntohs(arp->ar_pro));
        unsigned char *ptr = (unsigned char *)(arp + 1);
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x | Sender IP: %d.%d.%d.%d\n",
               ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5],
               ptr[6], ptr[7], ptr[8], ptr[9]);
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x | Target IP: %d.%d.%d.%d\n",
               ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15],
               ptr[16], ptr[17], ptr[18], ptr[19]);
    } else if (etype == 0x86DD) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
        printf("[IPv6 Header]\n");
        printf("Src IP: %s | Dst IP: %s\n", src, dst);
        printf("Hop Limit: %d | Next Header: %d | Payload Len: %d\n",
               ip6->ip6_hlim, ip6->ip6_nxt, ntohs(ip6->ip6_plen));
    }

    printf("----------------------------------------------------------\n");
}


void freestorage()
{
    if (pktarray != NULL)
    {
        for (int i = 0; i < pktcount; i++)
        {
            free((u_char *)pktarray[i].data);
        }
        free(pktarray);
        pktarray = NULL;
        pktcount = 0;
    }
}

void storepkt(const struct pcap_pkthdr *header, const u_char *data)
{
    if (pktarray == NULL)
    {
        pktarray = (storedpkt *)malloc(MAX * sizeof(storedpkt));
        pktcount = 0;
    }
    if (pktcount < MAX)
    {
        pktarray[pktcount].header = *header;
        pktarray[pktcount].data = (u_char *)malloc(header->caplen);
        memcpy((u_char *)pktarray[pktcount].data, data, header->caplen);
        pktcount++;
    }

    if (pktcount == MAX)
    {
        printf("[C-Shark] Packet storage full. Further packets will not be stored.\n");
    }
}

// LLM GENERATED CODE STARTS HERE //
void hex_dump(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i += 16)
    {

        // Print hex bytes
        for (int j = 0; j < 16; j++)
        {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");

            // Add extra space in middle
            if (j == 7)
                printf(" ");
        }

        // Print ASCII
        for (int j = 0; j < 16 && i + j < len; j++)
        {
            uint8_t c = data[i + j];
            if (c >= 32 && c <= 126) // printable ASCII
                printf("%c", c);
            else
                printf(".");
        }
        printf("\n");
    }
}
// LLM GENERATED CODE ENDS HERE //

pcap_t *handle = NULL;

void signal_handler(int signum)
{
    if (handle != NULL)
    {
        pcap_breakloop(handle);
    }
}

// void print_hex_prefix(const u_char *data, int len, int prefix_len)
// {
//     for (int i = 0; i < len && i < prefix_len; i++)
//         printf("%02x ", data[i]);
// }

struct cb_ctx
{
    unsigned long pkt_id;
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct cb_ctx *ctx = (struct cb_ctx *)args;
    ctx->pkt_id++;

    if (!flag)
        storepkt(header, packet);

    time_t sec = header->ts.tv_sec;


    printf("\n[C-Shark] --- Packet %lu ---\n", ctx->pkt_id);
    printf("Timestamp : %ld.%06ld\n",(long)sec,(long)header->ts.tv_usec);
    printf("Length  : %u bytes\n", header->caplen);
    // printf("Bytes[0..15]: ");
    // print_hex_prefix(packet, header->caplen, 32);

    struct ether_header *eth = (struct ether_header *)packet;
    printf("L2(Ethernet):\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    uint16_t ethertype = ntohs(eth->ether_type);
    const char *etype = "Unknown";
    switch (ethertype)
    {
    case 0x0800:
        etype = "IPv4";
        break;
    case 0x0806:
        etype = "ARP";
        break;
    case 0x86DD:
        etype = "IPv6";
        break;
    default:
        etype = "Unknown";
        break;
    }
    printf("Ether Type : %s (0x%04x)\n", etype, ethertype);

    if (ethertype == 0x0800)
    {
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
        struct in_addr src_addr, dst_addr;

        src_addr.s_addr = ip->saddr;
        dst_addr.s_addr = ip->daddr;

        printf("L3(IPv4) || Source IP: %s\n", inet_ntoa(src_addr));
        printf("L3(IPv4) || Destination IP: %s\n", inet_ntoa(dst_addr));

        if (ip->protocol == 6)
        {
            printf("Protocol : TCP(%d)\n", ip->protocol);
        }
        else if (ip->protocol == 17)
        {
            printf("Protocol : UDP(%d)\n", ip->protocol);
        }
        else
        {
            printf("Protocol : Unknown(Protocol Number - %d)\n", ip->protocol);
        }

    // Packet ID
    printf("Packet ID: %u (0x%04x)\n", ntohs(ip->id), ntohs(ip->id));

    /* Decode IPv4 fragmentation flags (Reserved, DF, MF) from frag_off */
    uint16_t frag = ntohs(*(uint16_t *)(&ip->frag_off));
    int flag_reserved = (frag & 0x8000) ? 1 : 0;
    int flag_df = (frag & 0x4000) ? 1 : 0;
    int flag_mf = (frag & 0x2000) ? 1 : 0;

    printf("TTL : %d | Header length : %d bytes \n", ip->ttl, ip->ihl * 4);
    printf("IP Flags: [Reserved:%d DF:%d MF:%d]\n", flag_reserved, flag_df, flag_mf);

        if (ip->protocol == 6)
        {
            // decode tcp
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip->ihl * 4);

            printf("Source Port : %d\n", ntohs(tcp->source));
            printf("Destination Port : %d", ntohs(tcp->dest));

            printf("Seq Num: %u\n", ntohl(tcp->seq));
            printf("Ack Num: %u\n", ntohl(tcp->ack_seq));

            printf("Flags: ");
            if (tcp->fin)
                printf("FIN ");
            if (tcp->syn)
                printf("SYN ");
            if (tcp->rst)
                printf("RST ");
            if (tcp->psh)
                printf("PSH ");
            if (tcp->ack)
                printf("ACK ");
            if (tcp->urg)
                printf("URG ");

            printf("\n");

            printf("Window Size: %u\n", ntohs(tcp->window));
            printf("Checksum: 0x%04x\n", ntohs(tcp->check));

            if (ntohs(tcp->dest) == 80)
            {
                printf("L7: Payload identified as HTTP on port %d\n", ntohs(tcp->dest));
                int plen = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
                printf("Length of payload is %d bytes\n", plen);

                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);

                // LLM GENERATED CODE STARTS HERE //
                int ip_header_len = ip->ihl * 4;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
                // LLM GENERATED CODE ENDS HERE //
            }
            else if (ntohs(tcp->dest) == 443)
            {
                printf("L7: Payload identified as HTTPS on port %d\n", ntohs(tcp->dest));

                int plen = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
                printf("Length of payload is %d bytes\n", plen);
                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);
                int ip_header_len = ip->ihl * 4;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else
            {
                int ip_header_len = ip->ihl * 4;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *pl = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                printf("L7: Unknown Payload - %d bytes\n", payload_len);
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(pl, to_dump);
            }
        }
        else if (ip->protocol == 17)
        {
            // decode udp
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + ip->ihl * 4);

            printf("L4(UDP):\n");
            printf("Source Port : %d\n", ntohs(udp->source));
            printf("Destination Port : %d\n", ntohs(udp->dest));
            printf("Length : %d bytes \n", ntohs(udp->len));
            printf("Checksum : 0x%04x \n", ntohs(udp->check));

            if (ntohs(udp->dest) == 80)
            {
                printf("L7: Payload identified as HTTP on port %d\n", ntohs(udp->dest));
                int plen = ntohs(ip->tot_len) - (ip->ihl * 4) - (udp->len);
                printf("Length of payload is %d bytes\n", plen);

                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);

                int ip_header_len = ip->ihl * 4;
                int udp_header_len = udp->len;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - udp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else if (ntohs(udp->dest) == 443)
            {
                printf("L7: Payload identified as HTTPS on port %d\n", ntohs(udp->dest));

                int plen = ntohs(ip->tot_len) - (ip->ihl * 4) - (udp->len);
                printf("Length of payload is %d bytes\n", plen);
                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);
                int ip_header_len = ip->ihl * 4;
                int udp_header_len = udp->len;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - udp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else
            {
                int ip_header_len = ip->ihl * 4;
                int udp_header_len = sizeof(struct udphdr);
                const uint8_t *pl = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
                int payload_len = ntohs(ip->tot_len) - ip_header_len - udp_header_len;
                if (payload_len < 0) payload_len = 0;
                printf("L7: Unknown Payload - %d bytes\n", payload_len);
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(pl, to_dump);
            }
        }
    }
    else if (ethertype == 0x86DD)
    {
        struct ip6_hdr *ip = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        struct in6_addr src_addr, dst_addr;

        src_addr = ip->ip6_src;
        dst_addr = ip->ip6_dst;
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &src_addr, src_str, sizeof(src_str));
        inet_ntop(AF_INET6, &dst_addr, dst_str, sizeof(dst_str));

        printf("L3(IPv6) || Source IP: %s\n", src_str);
        printf("L3(IPv6) || Destination IP: %s\n", dst_str);

        if (ip->ip6_nxt == 6)
        {
            printf("Protocol : TCP(%d)\n", ip->ip6_nxt);

            // decode tcp
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + 40);

            printf("Source Port : %d\n", ntohs(tcp->source));
            printf("Destination Port : %d", ntohs(tcp->dest));

            printf("Seq Num: %u\n", ntohl(tcp->seq));
            printf("Ack Num: %u\n", ntohl(tcp->ack_seq));

            printf("Flags: ");
            if (tcp->fin)
                printf("FIN ");
            if (tcp->syn)
                printf("SYN ");
            if (tcp->rst)
                printf("RST ");
            if (tcp->psh)
                printf("PSH ");
            if (tcp->ack)
                printf("ACK ");
            if (tcp->urg)
                printf("URG ");

            printf("\n");

            printf("Window Size: %u\n", ntohs(tcp->window));
            printf("Checksum: 0x%04x\n", ntohs(tcp->check));

            if (ntohs(tcp->dest) == 80)
            {
                printf("L7: Payload identified as HTTP on port %d\n", ntohs(tcp->dest));
                int plen = ntohs(ip->ip6_plen) - (tcp->doff * 4);
                printf("Length of payload is %d bytes\n", plen);

                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);

                int ip_header_len = 40;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->ip6_plen) - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else if (ntohs(tcp->dest) == 443)
            {
                printf("L7: Payload identified as HTTPS on port %d\n", ntohs(tcp->dest));

                int plen = ntohs(ip->ip6_plen) - (tcp->doff * 4);
                printf("Length of payload is %d bytes\n", plen);
                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);
                int ip_header_len = 40;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->ip6_plen) - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else
            {
                int ip_header_len = 40;
                int tcp_header_len = tcp->doff * 4;
                const uint8_t *pl = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
                int payload_len = ntohs(ip->ip6_plen) - tcp_header_len;
                if (payload_len < 0) payload_len = 0;
                printf("L7: Unknown Payload - %d bytes\n", payload_len);
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(pl, to_dump);
            }
        }
        else if (ip->ip6_nxt == 17)
        {
            printf("Protocol : UDP(%d)\n", ip->ip6_nxt);

            // decode udp
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ether_header) + 40);

            printf("L4(UDP):\n");
            printf("Source Port : %d\n", ntohs(udp->source));
            printf("Destination Port : %d\n", ntohs(udp->dest));
            printf("Length : %d bytes \n", ntohs(udp->len));
            printf("Checksum : 0x%04x \n", ntohs(udp->check));

            if (ntohs(udp->dest) == 53)
            {
                printf("L7: Payload identified as DNS on port %d\n", ntohs(udp->dest));

                int plen = ntohs(ip->ip6_plen) - (udp->len);
                printf("Length of payload is %d bytes\n", plen);
                int plen2 = plen < 64 ? plen : 64;
                printf("First %d bytes of payload (in ascii hex dump): ", plen2);
                int ip_header_len = 40;
                int udp_header_len = udp->len;
                const uint8_t *payload = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
                int payload_len = ntohs(ip->ip6_plen) - udp_header_len;
                if (payload_len < 0) payload_len = 0;
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(payload, to_dump);
            }
            else
            {
                /* Unknown L7 for IPv6 UDP: still show payload */
                int ip_header_len = 40;
                int udp_header_len = sizeof(struct udphdr);
                const uint8_t *pl = packet + sizeof(struct ether_header) + ip_header_len + udp_header_len;
                int payload_len = ntohs(ip->ip6_plen) - udp_header_len;
                if (payload_len < 0) payload_len = 0;
                printf("L7: Unknown Payload - %d bytes\n", payload_len);
                int to_dump = payload_len > 0 ? (payload_len < 64 ? payload_len : 64) : 0;
                if (to_dump > 0) hex_dump(pl, to_dump);
            }
        }
        else
        {
            printf("Protocol : Unknown(%d)\n", ip->ip6_nxt);
        }

        printf("Hop Limit : %d bytes \n", ip->ip6_hlim);
        printf("Payload Length : %d bytes \n", ntohs(ip->ip6_plen));
        printf("Traffic class : %d bytes \n", ntohl(ip->ip6_flow) >> 20);
        printf("Flow Label : %d bytes \n", ntohl(ip->ip6_flow) & 0x000FFFFF);
    }
    else if (ethertype == 0x0806)
    { // LLM GENERATED STARTS HERE //
        struct arphdr *arp = (struct arphdr *)(packet + sizeof(struct ether_header));
        printf("L3(ARP):\n");
        printf("Operation: %s (%d)\n", ntohs(arp->ar_op) == 1 ? "Request" : "Reply", ntohs(arp->ar_op));
        printf("Hardware Type: %d\n", ntohs(arp->ar_hrd));
        printf("Protocol Type: 0x%04x\n", ntohs(arp->ar_pro));
        printf("Hardware Length: %d\n", arp->ar_hln);
        printf("Protocol Length: %d\n", arp->ar_pln);

        unsigned char *arp_ptr = (unsigned char *)(arp + 1);
        printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_ptr[0], arp_ptr[1], arp_ptr[2],
               arp_ptr[3], arp_ptr[4], arp_ptr[5]);
        printf("Sender IP: %d.%d.%d.%d\n",
               arp_ptr[6], arp_ptr[7], arp_ptr[8], arp_ptr[9]);
        printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               arp_ptr[10], arp_ptr[11], arp_ptr[12],
               arp_ptr[13], arp_ptr[14], arp_ptr[15]);
        printf("Target IP: %d.%d.%d.%d\n", arp_ptr[16], arp_ptr[17], arp_ptr[18], arp_ptr[19]);
        // LLM GENERATED CODE ENDS HERE //
    }

    printf("\n");
    fflush(stdout);
}

void inspect()
{
    if (pktarray == NULL || pktcount == 0)
    {
        printf("First run a session to store and inspect packets.\n");
        return;
    }
    else
    {
        printf("Displaying last %d packets:\n", pktcount);
        flag = 1;
        struct cb_ctx ctx = {0};
        for (int i = 0; i < pktcount; i++)
        {
            packet_handler((u_char *)&ctx, &pktarray[i].header, pktarray[i].data);
        }

        flag = 0;
    }
}

int main()
{
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces...\n");

    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (NOt found 404)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure libpcap is installed.\n");
        return -1;
    }

    int inum;
    printf("\nSelect an interface to sniff (1-%d): ", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("Interface number is not in range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    d = alldevs;
    for (int j = 0; j < inum - 1; j++)
        d = d->next;

    printf("\n[C-Shark] Interface '%s' selected.\n", d->name);

    signal(SIGINT, signal_handler);

    int choice;
    while (1)
    {
        printf("\nMain Menu:\n");
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Deep Inspect of a single packet\n");
        printf("4. Exit C-Shark\n");

        printf("\nEnter your choice: ");
        if (scanf("%d", &choice) != 1)
        {

            while (getchar() != '\n')
            {
            }
            continue;
        }

        if (choice == 1)
        {
            freestorage();
            char errbuf2[PCAP_ERRBUF_SIZE];
            handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf2);
            if (handle == NULL)
            {
                fprintf(stderr, "Error opening device %s: %s\n", d->name, errbuf2);
                continue;
            }

            printf("\n[C-Shark] Sniffing started on %s...\n", d->name);
            printf("[Press Ctrl+C to stop]\n");

            // LLM GENERATED CODE STARTS HERE //
            struct cb_ctx ctx = {0};
            // LLM GENERATED CODE ENDS HERE //

            // LLM GENERATED CODE STARTS HERE //
            pcap_loop(handle, 0, packet_handler, (u_char *)&ctx);
            // LLM GENERATED CODE ENDS HERE //

            pcap_close(handle);
            printf("\n[C-Shark] Capture stopped. Returning to menu...\n");
        }
        else if (choice == 4)
        {
            printf("[C-Shark] Exiting.\n");
            pcap_breakloop(handle);
            exit(0);
        }
        else if (choice == 2)
        {
            freestorage();
            char errbuf2[PCAP_ERRBUF_SIZE];
            handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf2);
            if (handle == NULL)
            {
                fprintf(stderr, "Error opening device %s: %s\n", d->name, errbuf2);
                continue;
            }

            printf("Welcome to the filtered content shark\n");
            printf("You can select any one option only\n");
            printf("1. HTTP\n");
            printf("2. HTTPS\n");
            printf("3. ARP\n");
            printf("4. TCP\n");
            printf("5. UDP\n");
            printf("6. DNS\n");

            printf("Enter your choice: ");
            int ch;
            if (scanf("%d", &ch) != 1)
            {

                while (getchar() != '\n')
                {
                }
                continue;
            }
            if (ch < 1 || ch > 6)
            {
                printf("Invalid choice\n");
                continue;
            }
            printf("You selected option %d\n", ch);

            const char *filter;
            switch (ch)
            {
            case 1:
                filter = "tcp port 80";
                break;
            case 2:
                filter = "tcp port 443";
                break;
            case 3:
                filter = "arp";
                break;
            case 4:
                filter = "tcp";
                break;
            case 5:
                filter = "udp";
                break;
            case 6:
                filter = "udp port 53";
                break;
            default:
                filter = "";
                break;
            }

            struct bpf_program fp;
            if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
            {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                pcap_close(handle);
                continue;
            }

            if (pcap_setfilter(handle, &fp) == -1)
            {
                fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
                pcap_freecode(&fp);
                pcap_close(handle);
                continue;
            }

            printf("\n[C-Shark] Sniffing started on %s with filter '%s'...\n", d->name, filter);
            printf("[Press Ctrl+C to stop]\n");
            struct cb_ctx ctx = {0};
            pcap_loop(handle, 0, packet_handler, (u_char *)&ctx);
            pcap_freecode(&fp);
            pcap_close(handle);

            printf("\n[C-Shark] Capture stopped. Returning to menu...\n");
        }
        else if (choice == 3)
        {
            if (pktarray == NULL || pktcount == 0)
            {
                printf("[C-Shark] No packets captured yet.\n");
                continue;
            }

            show_summary();

            printf("\nEnter Packet ID to inspect in depth (1-%d): ", pktcount);
            int pid;
            if (scanf("%d", &pid) != 1 || pid < 1 || pid > pktcount)
            {
                printf("Invalid ID.\n");
                continue;
            }

            deep_inspect(pid - 1); 
        }
        else
        {
            printf("[C-Shark] Feature not implemented yet.\n");
        }
    }

    pcap_freealldevs(alldevs);
    return 0;
}
