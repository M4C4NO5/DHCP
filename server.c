#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define CIDR_NOTATION "192.0.0.1/19"
#define LEASE_TIME 3600 // 1 hour
#define DNS_SERVER "8.8.8.8" // Example DNS server

typedef struct {
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

typedef struct {
    struct in_addr ip;
    time_t lease_start;
    uint8_t chaddr[16];
} IPLease;

IPLease ip_leases[256];
int lease_count = 0;

struct in_addr network_address;
struct in_addr subnet_mask;
struct in_addr broadcast_address;
struct in_addr default_gateway;
struct in_addr ip_range_start;
struct in_addr ip_range_end;

void initialize_network() {
    char ip_str[16];
    int prefix_len;
    sscanf(CIDR_NOTATION, "%[^/]/%d", ip_str, &prefix_len);

    inet_pton(AF_INET, ip_str, &network_address);
    
    uint32_t mask = 0xffffffff << (32 - prefix_len);
    subnet_mask.s_addr = htonl(mask);

    broadcast_address.s_addr = network_address.s_addr | ~subnet_mask.s_addr;
    
    // Calculate default gateway (first usable IP in the network)
    default_gateway.s_addr = htonl(ntohl(network_address.s_addr) + 1);

    // Calculate IP range (10 IPs for testing)
    ip_range_start.s_addr = htonl(ntohl(network_address.s_addr) + 2);
    ip_range_end.s_addr = htonl(ntohl(ip_range_start.s_addr) + 9);

    printf("Network: %s\n", inet_ntoa(network_address));
    printf("Subnet Mask: %s\n", inet_ntoa(subnet_mask));
    printf("Broadcast: %s\n", inet_ntoa(broadcast_address));
    printf("Default Gateway: %s\n", inet_ntoa(default_gateway));
    printf("IP Range Start: %s\n", inet_ntoa(ip_range_start));
    printf("IP Range End: %s\n", inet_ntoa(ip_range_end));
}

int is_ip_in_range(struct in_addr ip) {
    return (ntohl(ip.s_addr) >= ntohl(ip_range_start.s_addr) && ntohl(ip.s_addr) <= ntohl(ip_range_end.s_addr));
}

struct in_addr get_available_ip() {
    struct in_addr ip = ip_range_start;
    for (uint32_t i = 0; i <= ntohl(ip_range_end.s_addr) - ntohl(ip_range_start.s_addr); i++) {
        ip.s_addr = htonl(ntohl(ip_range_start.s_addr) + i);
        int available = 1;
        for (int j = 0; j < lease_count; j++) {
            if (ip_leases[j].ip.s_addr == ip.s_addr) {
                available = 0;
                break;
            }
        }
        if (available) return ip;
    }
    ip.s_addr = INADDR_NONE;
    return ip;
}

void handle_dhcp_discover(int sockfd, DHCPMessage *msg, struct sockaddr_in *client_addr) {
    struct in_addr available_ip = get_available_ip();
    if (available_ip.s_addr == INADDR_NONE) {
        printf("No available IP addresses\n");
        return;
    }

    DHCPMessage offer_msg;
    memset(&offer_msg, 0, sizeof(offer_msg));
    offer_msg.op = 2; // BOOTREPLY
    offer_msg.htype = msg->htype;
    offer_msg.hlen = msg->hlen;
    offer_msg.xid = msg->xid;
    memcpy(offer_msg.chaddr, msg->chaddr, 16);
    offer_msg.yiaddr = available_ip.s_addr;
    offer_msg.flags = htons(0x8000); // Broadcast flag

    // Set DHCP options
    uint8_t *options = offer_msg.options;
    options[0] = 0x63; // Magic cookie
    options[1] = 0x82;
    options[2] = 0x53;
    options[3] = 0x63;

    options[4] = 53; // DHCP Message Type
    options[5] = 1;  // Length
    options[6] = 2;  // DHCPOFFER

    options[7] = 51; // IP Address Lease Time
    options[8] = 4;  // Length
    uint32_t lease_time = htonl(LEASE_TIME);
    memcpy(&options[9], &lease_time, 4);

    options[13] = 1; // Subnet Mask
    options[14] = 4; // Length
    memcpy(&options[15], &subnet_mask, 4);

    options[19] = 6; // DNS Server
    options[20] = 4; // Length
    struct in_addr dns_server;
    inet_aton(DNS_SERVER, &dns_server);
    memcpy(&options[21], &dns_server, 4);

    options[25] = 3; // Router (Default Gateway)
    options[26] = 4; // Length
    memcpy(&options[27], &default_gateway, 4);

    options[31] = 255; // End option

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = client_addr->sin_port;
    dest_addr.sin_addr = client_addr->sin_addr;

    ssize_t sent_len = sendto(sockfd, &offer_msg, sizeof(offer_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent_len < 0) {
        perror("Error sending DHCP OFFER");
    } else {
        printf("Sent DHCP OFFER to %s\n", inet_ntoa(dest_addr.sin_addr));
    }
}

void handle_dhcp_request(int sockfd, DHCPMessage *msg, struct sockaddr_in *client_addr) {
    struct in_addr requested_ip;
    requested_ip.s_addr = msg->yiaddr;

    if (!is_ip_in_range(requested_ip)) {
        printf("Requested IP out of range %s\n", inet_ntoa(requested_ip));
        return;
    }

    for (int i = 0; i < lease_count; i++) {
        if (ip_leases[i].ip.s_addr == requested_ip.s_addr) {
            printf("IP already leased\n");
            return;
        }
    }

    ip_leases[lease_count].ip = requested_ip;
    ip_leases[lease_count].lease_start = time(NULL);
    memcpy(ip_leases[lease_count].chaddr, msg->chaddr, 16);
    lease_count++;

    DHCPMessage ack_msg;
    memset(&ack_msg, 0, sizeof(ack_msg));
    ack_msg.op = 2; // BOOTREPLY
    ack_msg.htype = msg->htype;
    ack_msg.hlen = msg->hlen;
    ack_msg.xid = msg->xid;
    memcpy(ack_msg.chaddr, msg->chaddr, 16);
    ack_msg.yiaddr = requested_ip.s_addr;

    // Set DHCP options
    uint8_t *options = ack_msg.options;
    bzero(options, sizeof(ack_msg.options));
    options[0] = 0x63; // Magic cookie
    options[1] = 0x82;
    options[2] = 0x53;
    options[3] = 0x63;

    options[4] = 53; // DHCP Message Type
    options[5] = 1;  // Length
    options[6] = 5;  // DHCPACK

    options[7] = 51; // IP Address Lease Time
    options[8] = 4;  // Length
    uint32_t lease_time = htonl(LEASE_TIME);
    memcpy(&options[9], &lease_time, 4);

    options[13] = 1; // Subnet Mask
    options[14] = 4; // Length
    memcpy(&options[15], &subnet_mask, 4);

    options[19] = 6; // DNS Server
    options[20] = 4; // Length
    struct in_addr dns_server;
    inet_aton(DNS_SERVER, &dns_server);
    memcpy(&options[21], &dns_server, 4);

    options[25] = 3; // Router (Default Gateway)
    options[26] = 4; // Length
    memcpy(&options[27], &default_gateway, 4);

    options[31] = 255; // End option

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = client_addr->sin_port;
    dest_addr.sin_addr = client_addr->sin_addr;

    sendto(sockfd, &ack_msg, sizeof(ack_msg), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("Sent DHCP ACK to %s\n", inet_ntoa(dest_addr.sin_addr));
}

void handle_dhcp_release(DHCPMessage *msg) {
    struct in_addr released_ip;
    released_ip.s_addr = msg->ciaddr;

    for (int i = 0; i < lease_count; i++) {
        if (ip_leases[i].ip.s_addr == released_ip.s_addr && memcmp(ip_leases[i].chaddr, msg->chaddr, 16) == 0) {
            printf("Releasing IP: %s\n", inet_ntoa(released_ip));
            // Shift remaining leases down
            for (int j = i; j < lease_count - 1; j++) {
                ip_leases[j] = ip_leases[j + 1];
            }
            lease_count--;
            return;
        }
    }
    printf("IP not found for release: %s\n", inet_ntoa(released_ip));
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    DHCPMessage *dhcp_msg;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(1);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);

    // Bind socket to address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(sockfd);
        exit(1);
    }

    initialize_network();

    printf("DHCP server is running...\n");

    while (1) {
        // Receive DHCP message
        ssize_t recv_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len < 0) {
            perror("Error receiving data");
            continue;
        }

        dhcp_msg = (DHCPMessage *)buffer;

        // Process DHCP message
        switch (dhcp_msg->options[6]) {
            case 1: // DHCP DISCOVER
                handle_dhcp_discover(sockfd, dhcp_msg, &client_addr);
                break;
            case 3: // DHCP REQUEST
                handle_dhcp_request(sockfd, dhcp_msg, &client_addr);
                break;
            case 7: // DHCP RELEASE
                handle_dhcp_release(dhcp_msg);
                break;
            default:
                printf("Unknown DHCP message type\n");
                break;
        }
    }

    close(sockfd);
    return 0;
}