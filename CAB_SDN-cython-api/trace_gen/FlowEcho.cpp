#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>
#include "PcapHeader.hpp"
#include <signal.h>
#include <getopt.h>

#define MAX_ETHER_FRAME_LEN 1514
#define READ_TIMEOUT 1000

using namespace std;
namespace fs = boost::filesystem;
namespace io = boost::iostreams;
static volatile int keep_running = 1;
using std::cout;
using std::cerr;
using std::endl;

void got_signal(){
    keep_running = 0;
}

void print_help() {
    cerr << "Usage: FlowEcho {-i interface --ipv6/ipv4}";
    cerr << endl;
}

int main(int argc, char * argv[]) {
    /* configuration  */
    char if_name[10] = "";
    int ipv6_flag = 0;

    pcap_t * pd = nullptr;
    struct pcap_pkthdr header;
    char pebuf[PCAP_ERRBUF_SIZE];
    const unsigned char * packet;
    
    int getopt_res;
    while (1) {
        static struct option tracegen_options[] = {
            {"ipv6",        no_argument,                &ipv6_flag, 1},
            {"ipv4",        no_argument,                &ipv6_flag, 0},
            {"help",        no_argument,                0, 'h'},
            {"interface",   required_argument,          0, 'i'},
            {0,             0,                          0,  0}
        };

        int option_index = 0;

        getopt_res = getopt_long (argc, argv, "hf:i:s:F:",
                                  tracegen_options, &option_index);

        if (getopt_res == -1)
            break;

        switch (getopt_res) {
        case 0:
            if (tracegen_options[option_index].flag != 0)
                break;
        case 'i':
            strcpy(if_name, optarg);
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

    if (!strcmp(if_name, "")) {
        print_help();
        return 0;
    }

    pd = pcap_open_live(if_name, MAX_ETHER_FRAME_LEN, 1,
                        READ_TIMEOUT, pebuf);

    while (keep_running){
        cout << "wait for packet" << endl;
        packet = pcap_next(pd, &header);
	
	if (packet != NULL){
            if (ipv6_flag){
                pcap_sendpacket(pd, packet, 90);
	    }
	    else{
                pcap_sendpacket(pd, packet, 70);
            }
            cout << "got packet" << endl;
	}
    }

    cout << "closing...." <<endl;
    pcap_close(pd);
}
