#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>
#include <pcap.h>
#include "PcapHeader.hpp"
#include "Address.hpp"
using namespace std;

struct packet {
    packet():ether_h(),ip_h(),tcp_h() {};
    sniff_ethernet ether_h;
    sniff_ip ip_h;
    sniff_tcp tcp_h;
};

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

int main(int argc, char * argv[]) {
    cout << "unsigned int : " << sizeof(unsigned int) << endl;
    cout << "unsigned long : " << sizeof(unsigned long) << endl;
    cout << "ethernet packet length : " << sizeof(sniff_ethernet) << endl;
    cout << "ip packet length : " << sizeof(sniff_ip) << endl;
    cout << "tcp packet length : " << sizeof(sniff_tcp) << endl;
    cout << "full stack packet length : " << sizeof(packet) << endl;

    if(argc < 3) {
        cerr << "Usage: 2pcap_dump {path/to/trace/file/} {path/to/tcpdump/file}" << endl;
        return 1;
    }

    ifstream infile(argv[1]);
    if(!infile.is_open()) {
        cerr << "can not open trace file." << endl;
        return 2;
    }

    pcap_t* handle = pcap_open_dead(DLT_EN10MB,144);
    pcap_dumper_t* file = pcap_dump_open(handle,argv[2]);
    if(file == NULL) {
        cout << pcap_geterr(handle) << endl;
        return 3;
    }

    try {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        in.push(infile);
        string b; // tune curT to that of first packet

        unsigned int seq = 0;
        unsigned int ack = 0;
        while(getline(in, b)) {
            addr_5tup addr5(b, false);
            cerr << "converting.... : " << addr5.str_readable() << endl;
            cerr << addr5.addrs[2] << "\t" << addr5.addrs[3] << endl;
            pcap_pkthdr entry_h;
            entry_h.len = sizeof(sniff_ethernet) + sizeof(sniff_ip) + sizeof(sniff_tcp);
            entry_h.caplen = entry_h.len;
            entry_h.ts.tv_sec = (int)addr5.timestamp - 345;
            entry_h.ts.tv_usec =(addr5.timestamp - (long)addr5.timestamp) * 1000000;
            //cerr <<entry_h.ts.tv_sec <<"\t"<< entry_h.ts.tv_usec << endl;
            packet h;
            //set ip_packet
            h.ip_h.ip_len = htons(sizeof(sniff_ip) + sizeof(sniff_tcp));
            h.ip_h.ip_src.s_addr = htonl(addr5.addrs[0]);
            h.ip_h.ip_dst.s_addr = htonl(addr5.addrs[1]);
            //set tcp packet
            h.tcp_h.th_sport = htons((unsigned short)addr5.addrs[2]);
            h.tcp_h.th_dport = htons((unsigned short)addr5.addrs[3]);
            h.tcp_h.th_win = htons(256);
            h.tcp_h.th_ack = ack;
            h.tcp_h.th_seq = seq;
            seq++;
            ack++;

            unsigned char buffer[entry_h.len];
            memcpy(buffer,&(h.ether_h),sizeof(sniff_ethernet));
            memcpy(buffer + sizeof(sniff_ethernet), &(h.ip_h), sizeof(sniff_ip));
            memcpy(buffer + sizeof(sniff_ethernet) + sizeof(sniff_ip), &(h.tcp_h), sizeof(sniff_tcp));
            pcap_dump((u_char *)file,&entry_h, (unsigned char *)&buffer);
        }
    } catch (const io::gzip_error & e) {

        pcap_dump_flush(file);
        pcap_dump_close(file);
        cout<<e.what()<<endl;
        return 4;
    }
    pcap_dump_flush(file);
    pcap_dump_close(file);


    return 0;
}





