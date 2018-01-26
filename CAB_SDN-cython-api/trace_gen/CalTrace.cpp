#include <pcap.h>
#include <fstream>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <unordered_map>
#include <sys/time.h>
#include <vector>
#include "PcapHeader.hpp"
#include <iomanip>

using std::string;
using std::cerr;
using std::cout;
using std::endl;
using std::unordered_map;
using std::vector;
using std::ofstream;
using std::setw;
using std::setfill;

void print_help() {
    cerr << "Usage: FlowEcho -hs:r:b:o:" << endl;
    cerr << "                -h,--help" << endl;
    cerr << "                -s,--send   sender file" <<endl;
    cerr << "                -r,--recv   receiver file" <<endl;
    cerr << "                -b,--band   aggregation bands" <<endl;
    cerr << "                -o,--output output file prefix" <<endl;
}

typedef struct header_addr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_id;

    bool operator==(const header_addr &other) const {
        return (src_ip == other.src_ip &&
                dst_ip == other.dst_ip &&
                src_port == other.src_port &&
                dst_port == other.dst_port &&
                ip_id == other.ip_id);
    }
} header_addr;

struct header_hasher {
    std::size_t operator()(const header_addr& hd) const {
        using std::hash;

        return (hash<uint32_t>()(hd.src_ip) ^
                hash<uint32_t>()(hd.dst_ip) ^
                hash<uint16_t>()(hd.src_port) ^
                hash<uint16_t>()(hd.dst_port) ^
                hash<uint16_t>()(hd.ip_id));
    }
};

timeval tv_sub(const timeval & tv1, const timeval & tv2) {
    // asume tv1 > tv2
    int microseconds = (tv1.tv_sec - tv2.tv_sec) * 1000000 + ((int)tv1.tv_usec - (int)tv2.tv_usec);
    timeval tv;
    tv.tv_sec = microseconds/1000000;
    tv.tv_usec = microseconds%1000000;

    return tv;
}

int tv_cmp(const timeval & tv1, const timeval & tv2){
    if (tv1.tv_sec < tv2.tv_sec)
        return -1;
    if (tv1.tv_sec > tv2.tv_sec)
        return 1;

    if (tv1.tv_usec < tv2.tv_usec)
        return -1;
    if (tv1.tv_usec > tv2.tv_usec)
        return 1;
    
    return 0;
}

unordered_map<header_addr, vector<timeval>, header_hasher> record;

void dump_TCP_packet(const unsigned char * packet, struct timeval ts,
                     unsigned int capture_len) {
    if (capture_len < SIZE_ETHERNET) {
        return;
    }

    sniff_ethernet * eth = (sniff_ethernet *)packet;

    if (eth->ether_type != htons(ETHER_TYPE_IP))
        return;

    sniff_ip * ip = (sniff_ip *)(packet + sizeof(sniff_ethernet));

    header_addr header_val;
    header_val.src_ip = ip->ip_src.s_addr;
    header_val.dst_ip = ip->ip_dst.s_addr;
    header_val.src_port = *(uint16_t*)(eth->ether_shost + 4);
    header_val.dst_port = *(uint16_t*)(eth->ether_dhost + 4);
    header_val.ip_id = ip->ip_id;
    // cout<<"ip_id: "<<htons(ip->ip_id)<<endl;

    if (record.find(header_val) != record.end()) {
        record[header_val].push_back(ts);
    } else {
        vector<timeval> time_array(1, ts);
        record[header_val] = time_array;
    }
}

int main(int argc, char * argv[]) {
    char src_file[100] = "";
    char rcv_file[100] = "";
    char out_file[100] = "latency";
    int interval = 200;

    int getopt_res;
    while (1) {
        static struct option parser_options[] = {
            {"help",        no_argument,                0, 'h'},
            {"send",        required_argument,          0, 's'},
            {"recv",        required_argument,          0, 'r'},
            {"interval",    required_argument,          0, 'i'},
            {"output",      required_argument,          0, 'o'},
            {0,             0,                          0,  0}
        };

        int option_index = 0;

        getopt_res = getopt_long (argc, argv, "hs:r:i:o:",
                                  parser_options, &option_index);

        if (getopt_res == -1)
            break;

        switch (getopt_res) {
        case 0:
            if (parser_options[option_index].flag != 0)
                break;
        case 's':
            strcpy(src_file, optarg);
            break;
        case 'r':
            strcpy(rcv_file, optarg);
            break;
        case 'o':
            strcpy(out_file, optarg);
            break;
        case 'i':
            interval = atoi(optarg);
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

    if (!strcmp(src_file, "") || !strcmp(rcv_file, "")) {
        cout <<"mising input"<<endl;
        print_help();
        return 1;
    }

    // source file
    pcap_t * pd;
    char pebuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const unsigned char * packet;

    pd = pcap_open_offline(src_file, pebuf);

    while ((packet = pcap_next(pd, &header))) {
        dump_TCP_packet(packet, header.ts, header.caplen);
    }

    pcap_close(pd);

    // receive file
    pd = pcap_open_offline(rcv_file, pebuf);
    while ((packet = pcap_next(pd, &header))) {
        dump_TCP_packet(packet, header.ts, header.caplen);
    }
    pcap_close(pd);

    strcat(out_file, ".data");
    ofstream output(out_file);

    int miss_pkt = 0;
    int total_pkt = 0;

    timeval rtt_min;
    rtt_min.tv_sec = 1;
    rtt_min.tv_usec = 0;
    
    timeval rtt_max;
    rtt_max.tv_sec = 0;
    rtt_max.tv_usec = 0;

    vector<int> band_count(2000, 0);

    for (auto iter = record.begin(); iter != record.end(); ++iter) {
        ++total_pkt;

        if (iter->second.size() != 4) {
            ++miss_pkt;
            continue;
        }

        timeval src_del = tv_sub(iter->second[1], iter->second[0]);
        timeval dst_del = tv_sub(iter->second[3], iter->second[2]);
        timeval rtt = tv_sub(src_del, dst_del);

        if (rtt.tv_sec != 0){
            ++miss_pkt;
            cout << "too late: "<<rtt.tv_sec<<"."<<setw(6)<<setfill('0')<<rtt.tv_usec<<endl;
            continue;
        }

        output<<rtt.tv_sec<<"."<<setw(6)<<setfill('0')<<rtt.tv_usec<<"\t";
        output<<src_del.tv_usec<<"\t";
        output<<dst_del.tv_usec<<"\t";

        band_count[rtt.tv_usec/interval]++;

        if (tv_cmp(rtt, rtt_min) < 0)
            rtt_min = rtt;

        if (tv_cmp(rtt, rtt_max) > 0)
            rtt_max = rtt;

        for (timeval & ts : iter->second) {
            output<<ts.tv_sec<<"."<<ts.tv_usec<<"\t";
        }
        output<<endl;
    }
    output.close();

    cout<<"max rtt (us): "<<rtt_max.tv_sec<<setw(6)<<setfill('0')<<rtt_max.tv_usec<<endl;
    cout<<"min rtt (us): "<<rtt_max.tv_sec<<setw(6)<<setfill('0')<<rtt_min.tv_usec<<endl;
    cout<<"missed pkt: " << miss_pkt <<"  total pkt: "<<total_pkt<<endl;

    strcat(out_file, ".agg");
    ofstream output_agg(out_file);

    for (int i = 0; i < 2000; ++i){
        output_agg<<i*interval<<"\t\t\t"<<band_count[i]<<endl;
    }
    
    output_agg.close();
    return 0;
}
