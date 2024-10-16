#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE 1024
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 69

typedef struct
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
} DHCPMessage;

void read_dhcp_options(DHCPMessage *msg)
{
    uint8_t *options = msg->options;
    int i = 13; // Start after the magic cookie and the first option

    struct in_addr ip_addr;
    ip_addr.s_addr = msg->yiaddr;

    while (i < sizeof(msg->options) && options[i] != 255) // 255 is the END option
    {
        uint8_t option_type = options[i++];
        if (i >= sizeof(msg->options)) break;
        uint8_t option_length = options[i++];

        if (i + option_length > sizeof(msg->options)) {
            break;
        }

        switch (option_type)
        {
        case 1: // Subnet Mask
            {
                struct in_addr subnet;
                memcpy(&subnet.s_addr, &options[i], 4);
                printf("Subnet Mask: %s\n", inet_ntoa(subnet));
            }
            break;
        case 6: // DNS Server
            {
                struct in_addr dns;
                memcpy(&dns.s_addr, &options[i], 4);
                printf("DNS Server: %s\n", inet_ntoa(dns));
            }
            break;
        }

        i += option_length;
    }
}

void send_dhcp_discover(int sockfd, struct sockaddr_in *server_addr)
{
    DHCPMessage discover_msg;
    memset(&discover_msg, 0, sizeof(discover_msg));
    discover_msg.op = 1;                  // BOOTREQUEST
    discover_msg.htype = 1;               // Ethernet
    discover_msg.hlen = 6;                // MAC address length
    discover_msg.xid = htonl(0x12345678); // Transaction ID
    discover_msg.flags = htons(0x8000);   // Broadcast flag

    // Set DHCP options
    discover_msg.options[0] = 0x63; // Magic cookie
    discover_msg.options[1] = 0x82;
    discover_msg.options[2] = 0x53;
    discover_msg.options[3] = 0x63;
    discover_msg.options[4] = 53; // DHCP Message Type
    discover_msg.options[5] = 1;  // Length
    discover_msg.options[6] = 1;  // DHCPDISCOVER

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DHCP_SERVER_PORT);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0)
    {
        perror("setsockopt");
        close(sockfd);
        exit(1);
    }

    sendto(sockfd, &discover_msg, sizeof(discover_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("Sent DHCP DISCOVER\n");
}

void handle_dhcp_offer(int sockfd, DHCPMessage *offer_msg)
{
    struct in_addr offered_ip;
    offered_ip.s_addr = offer_msg->yiaddr;
    printf("Received DHCP OFFER: \nIP Address: %s\n", inet_ntoa(offered_ip));

    read_dhcp_options(offer_msg);
}

void send_dhcp_request(int sockfd, struct sockaddr_in *server_addr, DHCPMessage *offer_msg)
{
    DHCPMessage request_msg;
    memset(&request_msg, 0, sizeof(request_msg));
    request_msg.op = 1;                     // BOOTREQUEST
    request_msg.htype = 1;                  // Ethernet
    request_msg.hlen = 6;                   // MAC address length
    request_msg.xid = offer_msg->xid;       // Use the same transaction ID
    request_msg.flags = htons(0x8000);      // Broadcast flag
    request_msg.yiaddr = offer_msg->yiaddr; // Requested IP address

    request_msg.options[0] = 0x63; // Magic cookie
    request_msg.options[1] = 0x82;
    request_msg.options[2] = 0x53;
    request_msg.options[3] = 0x63;
    request_msg.options[4] = 53; // DHCP Message Type
    request_msg.options[5] = 1;  // Length
    request_msg.options[6] = 3;  // DHCP REQUEST
    request_msg.options[7] = 50; // Requested IP Address
    request_msg.options[8] = 4;  // Length

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DHCP_SERVER_PORT);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    sendto(sockfd, &request_msg, sizeof(request_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("Sent DHCP REQUEST\n");
}

void handle_dhcp_ack(int sockfd, DHCPMessage *ack_msg)
{
    struct in_addr assigned_ip;
    assigned_ip.s_addr = ack_msg->yiaddr;
    printf("Received DHCP ACK: \nIP Address: %s\n", inet_ntoa(assigned_ip));

    read_dhcp_options(ack_msg);
}

void send_dhcp_release(int sockfd, struct sockaddr_in *server_addr, DHCPMessage *ack_msg)
{
    DHCPMessage release_msg;
    memset(&release_msg, 0, sizeof(release_msg));
    release_msg.op = 1;                              // BOOTREQUEST
    release_msg.htype = 1;                           // Ethernet
    release_msg.hlen = 6;                            // MAC address length
    release_msg.xid = ack_msg->xid;                  // Use the same transaction ID
    release_msg.yiaddr = ack_msg->yiaddr;            // Client IP address
    memcpy(release_msg.chaddr, ack_msg->chaddr, 16); // Copy the client's MAC address

    // Set DHCP options
    uint8_t *options = release_msg.options;
    options[0] = 0x63; // Magic cookie
    options[1] = 0x82;
    options[2] = 0x53;
    options[3] = 0x63;

    options[4] = 53; // DHCP Message Type
    options[5] = 1;  // Length
    options[6] = 7;  // DHCPRELEASE

    options[7] = 54; // Server Identifier
    options[8] = 4;  // Length
    memcpy(&options[9], &ack_msg->siaddr, 4);

    options[13] = 255; // End option

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DHCP_SERVER_PORT);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    sendto(sockfd, &release_msg, sizeof(release_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("Sent DHCP RELEASE\n");
}

int main()
{
    int sockfd;
    struct sockaddr_in client_addr, server_addr;
    socklen_t server_len = sizeof(server_addr);
    char buffer[BUFFER_SIZE];
    DHCPMessage *dhcp_msg;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        exit(1);
    }

    // Configure client address
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(INADDR_ANY);
    client_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        perror("Error binding socket");
        close(sockfd);
        exit(1);
    }

    // Send DHCPDISCOVER
    send_dhcp_discover(sockfd, &server_addr);

    // Receive DHCPOFFER
    ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_len);
    if (recv_len < 0)
    {
        perror("Error receiving data");
        close(sockfd);
        exit(1);
    }
    dhcp_msg = (DHCPMessage *)buffer;
    handle_dhcp_offer(sockfd, dhcp_msg);

    // Send DHCPREQUEST
    send_dhcp_request(sockfd, &server_addr, dhcp_msg);

    // Receive DHCPACK
    recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&server_addr, &server_len);
    if (recv_len < 0)
    {
        perror("Error receiving data");
        close(sockfd);
        exit(1);
    }
    dhcp_msg = (DHCPMessage *)buffer;
    handle_dhcp_ack(sockfd, dhcp_msg);

    // Simulate some usage
    sleep(30);

    // Send DHCPRELEASE
    send_dhcp_release(sockfd, &server_addr, dhcp_msg);

    close(sockfd);
    printf("Client terminating after DHCP RELEASE\n");
    return 0;
}
