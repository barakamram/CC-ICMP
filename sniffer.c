/********************
*
* Barak Amram ID:209369289
* Liroy melamed ID:209366970
* Assignment number 5
* ICMP packets sniffer
*
********************/

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h> // To close without any warning


#define PACKET_LEN 512

int main()
{
    struct sockaddr s_addr;
    struct packet_mreq mr;

    // Create a raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Turn on promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    int data, count = 0;
    char buffer[IP_MAXPACKET];
    printf("Sniffing...\n\n");
    // Getting captured packets
    while (1)
    {
      data = recvfrom(sock, buffer, PACKET_LEN, 0, &s_addr, (socklen_t *)sizeof(s_addr));
      struct iphdr *ip_hdr = (struct iphdr *)(buffer + ETH_HLEN);

      // If the captured packet is an ICMP packet.
      if (ip_hdr->protocol == IPPROTO_ICMP)
      {
        struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));
        int type = (unsigned int)(icmp_hdr->type);
        int code = (unsigned int)(icmp_hdr->code);

        // ICMP header of type 8 is Echo & type 0 is Echo (Reply).
        // We capture our sent ping to 8.8.8.8(Echo) or Echo replies from 8.8.8.8 (Echo (Reply)).
        if (type == 0 || type == 8)
        {
          struct sockaddr_in src, dest;
          // source IP Address:
          memset(&src, 0, sizeof(src));
          src.sin_addr.s_addr = ip_hdr->saddr;
          // destination IP Address:
          memset(&dest, 0, sizeof(dest));
          dest.sin_addr.s_addr = ip_hdr->daddr;

          printf("********************\n"); // Packets separation
          printf("ICMP Packet Number %d:\n", ++count); // Number of ICMP packet
          printf(" * Source IP: %s\n", inet_ntoa(src.sin_addr)); // Source
          printf(" * Destination IP: %s\n", inet_ntoa(dest.sin_addr)); //Destination
          printf("ICMP Details:\n");
          printf(" * Type: %d\n * Code: %d\n", type,code); // Details(type & code)
        }
      }
    }
    close(sock);
    return 0;
}
