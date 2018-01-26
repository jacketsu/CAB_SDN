#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <fstream>
#include <string>
#include <set>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>
#include "PcapHeader.hpp"
#include "TimeSpec.hpp"
#include "Address.hpp"
#include <getopt.h>

#define MAX_ETHER_FRAME_LEN 1514
#define READ_TIMEOUT 1000

using namespace std;
namespace fs = boost::filesystem;
namespace io = boost::iostreams;

// std::set<string> flows;

// string str_readable(const addr_5tup & h){
//     stringstream ss;
//     for (uint32_t i = 0; i < 2; i++) {
//         for (uint32_t j = 0; j < 4; j++) {
//             ss << ((h.addrs[i] >> (24-8*j)) & ((1<<8)-1));
//             if (j!=3)
//                 ss<<".";
//         }
//         ss<<"\t";
//     }
//     for (uint32_t i = 2; i < 4; i++)
//         ss<<h.addrs[i]<<"\t";

//     return ss.str();
// }

int make_pkt(const addr_5tup & header, uint8_t ** data,
             uint32_t * pkt_len, uint16_t idx = 0) {
    uint32_t payload_size = sizeof(timespec);
    uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ip) +
                           sizeof(sniff_tcp) + payload_size;
    uint8_t * buffer = new uint8_t[buffer_size];

    memset(buffer, 0, buffer_size);

    sniff_ethernet * eth = (sniff_ethernet *)buffer;
    sniff_ip * ip = (sniff_ip *)(buffer+sizeof(sniff_ethernet));
    sniff_tcp * tcp = (sniff_tcp *)(buffer + sizeof(sniff_ethernet) +
                                    sizeof(sniff_ip));
    uint8_t * body = buffer + sizeof(sniff_ethernet) +
                     sizeof(sniff_ip) + sizeof(sniff_tcp);

    /* IPv4 4 tuple mapping -> TCP port to MAC  */
    /* map TCP port into mac for wildcard testing */
    *eth = sniff_ethernet();
    uint32_t src_port = htonl(header.addrs[2]);
    uint32_t dst_port = htonl(header.addrs[3]);
    memcpy(eth->ether_shost + 2, &src_port, 4);
    memcpy(eth->ether_dhost + 2, &dst_port, 4);

    /* IP source  */
    *ip = sniff_ip();
    *tcp = sniff_tcp();
    ip->ip_src.s_addr = htonl(header.addrs[0]);
    ip->ip_dst.s_addr = htonl(header.addrs[1]);
    ip->ip_len = htons(buffer_size - sizeof(sniff_ethernet));
    ip->ip_id = htons(idx);

    /* make time stamp */
    timespec * timestamp = (timespec *)body;
    clock_gettime(CLOCK_REALTIME,timestamp);

    *data = buffer;
    *pkt_len = buffer_size;

    return 0;
}

int make_pkt_ipv6(const addr_5tup & header, uint8_t ** data, uint32_t * pkt_len) {
    // uint32_t payload_size = sizeof(timespec);
    // uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ipv6) +
    //                       sizeof(sniff_tcp) + payload_size;
    uint32_t buffer_size = sizeof(sniff_ethernet) + sizeof(sniff_ipv6) +
                           sizeof(sniff_icmp);
    uint8_t * buffer = new uint8_t[buffer_size];

    memset(buffer, 0, buffer_size);

    sniff_ethernet * eth = (sniff_ethernet *)buffer;
    sniff_ipv6 * ip = (sniff_ipv6 *)(buffer+sizeof(sniff_ethernet));
    // sniff_tcp * tcp = (sniff_tcp *)(buffer + sizeof(sniff_ethernet) +
    sniff_icmp * icmp = (sniff_icmp *)(buffer + sizeof(sniff_ethernet) +
                                       sizeof(sniff_ipv6));
    // uint8_t * body = buffer + sizeof(sniff_ethernet) +
    //                 sizeof(sniff_ipv6) + sizeof(sniff_tcp);

    //DEBUG
    std::cout<<"sizeofEther: "<< sizeof(sniff_ethernet) << endl;
    std::cout<<"sizeOfIPv6: " << sizeof(sniff_ipv6) << endl;
    // std::cout<<"sizeofTcp:  " << sizeof(sniff_tcp) << endl;
    // std::cout<<"sizeOfbody: " << payload_size << endl;
    std::cout<<"sizeoficmp:  " << sizeof(sniff_icmp) << endl;
    std::cout<<"buffer :  "   << buffer_size << endl;
    // std::cout<<"before sniff_ethernet()\n";

    *eth = sniff_ethernet();
    eth->ether_type = htons(ETHER_TYPE_IPV6);
    unsigned char src_mac[ETHER_ADDR_LEN] = {0xa0, 0x36, 0x9f, 0x71, 0x14, 0x04};
    // unsigned char dst_mac[ETHER_ADDR_LEN] = {0xa0, 0x36, 0x9f, 0x71, 0x13, 0xfa};
    unsigned char dst_mac[ETHER_ADDR_LEN] = {0x33, 0x33, 0xff, 0x71, 0x13, 0xfa};
    memcpy(eth->ether_shost, &src_mac, ETHER_ADDR_LEN);
    memcpy(eth->ether_dhost, &dst_mac, ETHER_ADDR_LEN);

    /* Map ipv4:port to ipv6  */
    // TODO: check big edian/small edian
    std::cout<<"before map ipv4+port to ipv6"<<endl;
    *ip = sniff_ipv6();
    // *tcp = sniff_tcp();
    *(uint32_t *)(ip->ip_src.s6_addr + 12) = htonl(header.addrs[0]);
    *(uint32_t *)(ip->ip_src.s6_addr + 8) = htonl(header.addrs[2]);
    *(uint32_t *)(ip->ip_src.s6_addr + 4) = htonl(header.addrs[1]);
    *(uint32_t *)(ip->ip_src.s6_addr) = htonl(header.addrs[3]);

    unsigned char tar_ip[16] = {0xfe, 0x80, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,
                                0xa2, 0x36, 0x9f, 0xff,
                                0xfe, 0x71, 0x13, 0xfa
                               };
    unsigned char dst_ip[16] = {0xff, 0x02, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x01,
                                0xff, 0x71, 0x13, 0xfa
                               };
    unsigned char gen_ip[16] = {0xfe, 0x80, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,
                                0xa2, 0x36, 0x9f, 0xff,
                                0xfe, 0x71, 0x14, 0x04
                               };

    memcpy(ip->ip_dst.s6_addr, dst_ip, 16);
    memcpy(ip->ip_src.s6_addr, gen_ip, 16);

    ip->ip_len = htons(buffer_size - sizeof(sniff_ethernet) - sizeof(sniff_ip));
    ip->ip_nxt = 58;

    *icmp = sniff_icmp();
    memcpy(icmp->tar_ip.s6_addr, tar_ip, 16);
    memcpy(icmp->orig_mac, src_mac, 6);

    *data = buffer;
    *pkt_len = buffer_size;

    //DEBUG
    std::cout<<"before return of mk_pkt_ipv6"<<endl;
    return 0;
}

void print_help() {
    cerr << "Usage: FlowGen {-s stats_file -i interface -f trace_file -F factor -C pkt_count --ipv6/ipv4}";
    cerr << endl;
}

int main(int argc, char * argv[]) {
    /* configuration  */
    char trace_file_str[100];
    char if_name[10];
    char stat_file_str[100];
    int factor = 1;
    int ipv6_flag = 0;
    int max_pkt_cnt = 0;

    pcap_t * pd = nullptr;
    char pebuf[PCAP_ERRBUF_SIZE];

    int getopt_res;
    while (1) {
        static struct option tracegen_options[] = {
            {"help",        no_argument,                0, 'h'},
            {"ipv6",        no_argument,                &ipv6_flag, 1},
            {"ipv4",        no_argument,                &ipv6_flag, 0},
            {"file",        required_argument,          0, 'f'},
            {"interface",   required_argument,          0, 'i'},
            {"stats",       required_argument,          0, 's'},
            {"scale",       required_argument,          0, 'S'},
            {"count",       required_argument,          0, 'C'},
            {0,             0,                          0,  0}
        };

        int option_index = 0;

        getopt_res = getopt_long (argc, argv, "hf:i:s:F:C:",
                                  tracegen_options, &option_index);

        if (getopt_res == -1)
            break;

        switch (getopt_res) {
        case 0:
            if (tracegen_options[option_index].flag != 0)
                break;
        case 'C':
            max_pkt_cnt = atoi(optarg);
            break;
        case 'f':
            strcpy(trace_file_str, optarg);
            break;
        case 'i':
            strcpy(if_name, optarg);
            break;
        case 's':
            strcpy(stat_file_str, optarg);
            break;
        case 'F':
            factor = atoi(optarg);
            break;
        case 'h':
            print_help();
            return 0;
        case '?':
            print_help();
            return 0;
        default:
            abort();
        }
    }

    if (!strcmp(if_name, "") ||
            !strcmp(trace_file_str, "") ||
            !strcmp(stat_file_str, "")) {
        print_help();
        return 0;
    }

    pd = pcap_open_live(if_name, MAX_ETHER_FRAME_LEN, 1,
                        READ_TIMEOUT, pebuf);

    /* start sending  */
    ifstream trace_file(trace_file_str);

    if (!trace_file.is_open()) {
        cerr << "Can not open trace file : " << trace_file_str << endl;
        print_help();
        return 2;
    }

    try {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        in.push(trace_file);
        string line;
        TimeSpec zero, now;

        /* set birth time */
        clock_gettime(CLOCK_MONOTONIC, &zero.time_point_);

        uint16_t pkt_idx = 0;

        while(getline(in,line) && (max_pkt_cnt == 0 || pkt_idx < max_pkt_cnt)) {
            ++pkt_idx;

            addr_5tup pkt_header(line);

            uint8_t * pkt = nullptr;
            uint32_t  pkt_len = 0;

            /* set packet interval */
            TimeSpec next_pkt_ts(pkt_header.timestamp * factor);
            clock_gettime(CLOCK_MONOTONIC, &now.time_point_);

            if (now < zero + next_pkt_ts) {
                TimeSpec to_sleep = next_pkt_ts + zero - now;
                nanosleep(&to_sleep.time_point_, nullptr);
            }

            if (ipv6_flag) {
                make_pkt_ipv6(pkt_header, &pkt, &pkt_len);
            } else {
                make_pkt(pkt_header, &pkt, &pkt_len, pkt_idx);
            }

            int result = pcap_sendpacket(pd,pkt,pkt_len);

            delete [] pkt;
        }
    } catch(std::exception & e) {
        cerr << e.what() << endl;
    }
}
