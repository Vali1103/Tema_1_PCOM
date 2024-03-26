#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

// host to network long
uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t hostshort);
// network to host long
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);

// functie de transformare a unui nr in string cu format ip
char* int_to_ip(uint32_t ip_addr) {
    char* ip_str = malloc(16); 
    if (ip_str == NULL) {
        return NULL;
    }

    uint8_t* octeti = (uint8_t*) &ip_addr;
    
    sprintf(ip_str, "%d.%d.%d.%d", octeti[0], octeti[1], octeti[2], octeti[3]);
    return ip_str;
}

// functie de comparare a elementelor din tabela de rutare
// pentru qsort, sortare crescatoare dupa prefix apoi dupa mask
int compare(const void *a, const void *b) {
    const struct route_table_entry *entry_a = a;
    const struct route_table_entry *entry_b = b;
	
    if (entry_a->prefix < entry_b->prefix) {
        return -1;
    } else if (entry_a->prefix > entry_b->prefix) {
        return 1;
    } else {
		if (entry_a->mask < entry_b->mask)
			return -1;
		else if (entry_a->mask > entry_b->mask)
			return 1;
		else
        return 0;
    }
}

// functie de cautare iterativ binar, astfel cauta in tabela de rutare sortata mai usor
// pana in momentul cand adresa oferita este mai mica decat prefix, stiind ca 
// atunci cand se face and cu mask oricum da mai mic si nu exista sansa de a o gasi
int iterative_binary_search(struct route_table_entry* table_route, int n, uint32_t el){
	int idx = - 1;
	int mask = 0;
	for(int i = 0; i < n; i++){
		if(table_route[i].prefix == (el & table_route[i].mask ))
			if(table_route[i].mask > mask){
				mask = table_route[i].mask;
				idx = i;
			}
		if(table_route[i].prefix > el) {
			break;
			
		}
	}
	return idx;
}
uint32_t ip_string_to_int(char* ip_str) {
    struct in_addr addr;
    int result = inet_pton(AF_INET, ip_str, &addr);
    if (result == 0) {
        // Invalid IP address format
        return 0;
    } else if (result == -1) {
        // Failed to convert IP address
        return 0;
    }
    return addr.s_addr;
}

// functie de trimitere mesaj icmp TIME EXCEEDED si DESTINATION UNREACHEBLE
void trimite_icmp(struct iphdr * ip_hdr, struct ether_header *eth_hdr, int interface, char* buf, size_t len, int my_checksum, int type){
	char buffer[MAX_PACKET_LEN];
    memset(buffer, 0, MAX_PACKET_LEN);

	char *payload = calloc(8, sizeof(char));
	strncpy(payload, (char *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr)), 8);

	struct ether_header * pachet = (struct ether_header *)buffer;
	uint8_t temp[6];
	for(int i = 0; i < 6; i++){
		temp[i] = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = temp[i];
	}
	memcpy(pachet, eth_hdr, sizeof(struct ether_header));

	struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ether_header));
	memcpy(ip, ip_hdr, sizeof(struct iphdr));
	ip->protocol = 1;
	ip->ttl = 64;
	ip->daddr = ip_hdr->saddr;
	ip->saddr = htonl(ip_string_to_int(get_interface_ip(interface)));
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
	ip->check = htons(checksum((uint16_t *)ip, 20));

	struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp->code = 0;
	icmp->type = type;
	icmp->checksum = 0;
	icmp->checksum = htons(checksum((uint16_t *)icmp, sizeof(struct icmphdr)));

	struct iphdr *ip2 = (struct iphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(ip2, ip_hdr, sizeof(struct iphdr));
	ip2->check = my_checksum;

	char *p = (char *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));
	memcpy(p, payload, 8 * sizeof(char));

	len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8 * sizeof(char);
	send_to_link(interface, buffer, len);
}



int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// deschid tabela de routare inainte de a astepta mesajele deoarece e mult rapid de 
	// de a deschide inainte si a o sorta pentru totdeauna
	// deoarece nu e necesar sa o faca la fiecare pas
	struct route_table_entry *table_route = calloc(65000, sizeof(struct route_table_entry));
	int count = read_rtable(argv[1], table_route);

	//sortare crescator
	qsort(table_route, count, sizeof(struct route_table_entry), compare);
	
	while (1) {

		int interface;
		size_t len;
		
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		struct iphdr *ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
		if(ip_hdr == NULL)
			continue;
		if(eth_hdr == NULL)
			continue;

		char *ip = calloc(16 , sizeof(char));
		ip = int_to_ip(ip_hdr->daddr);
		
		
	 	if(strcmp(ip , get_interface_ip(interface)) == 0){

			//primire echo request si trimitere echo reply
			struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			uint8_t temp[6];
			for(int i = 0; i < 6; i++){
				temp[i] = eth_hdr->ether_dhost[i];
				eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
				eth_hdr->ether_shost[i] = temp[i];
			}
			
			icmp->type = 0;
			send_to_link(interface, buf, len);
			
			//routerul e destinatia si face ce vrea cu pachetul
			continue;
		} else {
			int check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			
			// verific checksum ul
			int my_checksum = checksum((uint16_t *)ip_hdr, 20);
			
			if(my_checksum == check){
				if(ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
					trimite_icmp(ip_hdr, eth_hdr, interface, buf, len, my_checksum, 11);	
					continue; // trebuie arunca TIME EXCEEDED
				} else {
					ip_hdr->ttl = ip_hdr->ttl - 1;
					//cautare in tabela de routare
					int idx = iterative_binary_search(table_route, count, ip_hdr->daddr);

					if(idx == -1){
						trimite_icmp(ip_hdr, eth_hdr, interface, buf, len, my_checksum, 3);
						//DESTINATION UNREACHABLE
						continue;
					} else {
						//s-a gasit o ruta si cea mai buna
						int new_checksum = checksum((uint16_t *)ip_hdr, 20);
						ip_hdr->check = htons(new_checksum);

						//6. rescriere adrese L2
						uint8_t *router_mac = calloc(6, sizeof(uint8_t));
						get_interface_mac(interface, router_mac);
						
						
						for(int i = 0; i < 6; i++)
							eth_hdr->ether_shost[i] = router_mac[i];
						struct arp_entry *table_arp = calloc(6 , sizeof(struct arp_entry));

						parse_arp_table("arp_table.txt", table_arp);
						for(int i = 0; i < 6; i++)
							if(table_route[idx].next_hop == table_arp[i].ip)
								for (int j = 0; j < 6; j++)
									eth_hdr->ether_dhost[j] = table_arp[i].mac[j];

						send_to_link(table_route[idx].interface, buf, len);
					}

				}
			} else {
				// pachet corupt
				continue;
			}

		}
		
		
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

