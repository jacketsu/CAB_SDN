#ifndef TRACEGEN_H
#define TRACEGEN_H

#include "headers.h"
#include "Address.hpp"
#include "Rule.hpp"
#include "RuleList.h"
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/copy.hpp>
#include <cassert>
#include <thread>
#include <future>
#include <mutex>
#include <atomic>
#include <chrono>
#include <set>
#include <map>

#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

using std::vector;
using std::string;
using std::atomic_uint;
using std::atomic_bool;
using std::mutex;
using boost::unordered_map;
using boost::unordered_set;
namespace fs = boost::filesystem;
namespace io = boost::iostreams;

/*
 * Usage:
 *   tracer tGen(rulelist pointer);
 *   tGen.setpara(parameter file);
 *   tGen.hotspot(reference file)
 *   pFlow_pruning_gen (objective synthetic trace directory)
 */

class tgen_para {
public:
    // basic parameter
    double flow_rate;
    double simuT;

    // locality traffic parameter
    double cold_prob;
    uint32_t hotspot_no;
    uint32_t scope[4];		    // hotspot probing scope
    uint32_t mut_scalar[2];     // mutate scale parameter
    bool prep_mutate;
    uint32_t hot_rule_thres;	// lower bound for indentify a hot rule
    uint32_t hot_candi_no;	    // number of hot candidate to generate
    
    string trace_root_dir;      // root directory of generated traces	
    string hotcandi_str;	    // hotspot candi file
    string hotspot_ref;         // hotspot reference file
    string flowInfoFile_str;    // first arr time of each flow
    
    // dynamics parameter
    bool evolving;
    double hotvtime;            // arrival interval of hot spot
    double evolving_time;       // ?? 
    size_t evolving_no;         // ??

    // trace source parameter 
    string pcap_dir;		    // original pcap trace direcotry
    string parsed_pcap_dir;	    // directory of parsed pcap file

    // bulk generate
    int bulk_no;
    int flow_rate_step;
    double cold_prob_step;
    int hotspot_no_step;

public:
    tgen_para();
    tgen_para(const tgen_para & another_para);
    tgen_para(string config_file);
};

class tracer {
    boost::log::sources::logger tracer_log;
public:
    tgen_para para; // TODO: this will replace all the parameters
    
    // double flow_rate;
    // double cold_prob;
    // uint32_t hotspot_no;
    // double hotvtime;
    // string trace_root_dir; 	

private:
    rule_list * rList;
    uint32_t flow_no;
    // double simuT;
    EpochT jesusBorn;
    atomic_uint total_packet;
    // string hotspot_ref;
    // double evolving_time;
    // size_t evolving_no;

    // locality traffic parameter
    // string hotcandi_str;	// hotspot candi file
    // uint32_t scope[4];		// hotspot probing scope
    // uint32_t hot_rule_thres;	// lower bound for indentify a hot rule
    // uint32_t hot_candi_no;	// number of hot candidate to generate


    // sources and gen
    // string flowInfoFile_str;    // first arr time of each flow
    // string pcap_dir;		// original pcap trace direcotry
    // string parsed_pcap_dir;	// directory of parsed pcap file

    // intermediate
    vector<string> to_proc_files;
    string gen_trace_dir;	// the directory for generating one specific trace

public:
    tracer();
    tracer(rule_list * rList, string para_file);

    /* parameter settings
     * 1. vector<fs::path> get_proc_files(string): the vector return version of trace_get_ts()
     * 2. print_setup (): print the current parameter setting
     */
    void get_proc_files();
    void print_setup() const;

    /* toolkit
     * 1. trace_get_ts(string trace_ts_file): get the timestamp of the first packet of the traces and record as "path \t ts"
     * 2. uint32_t count_proc(): counts the no. of processors in this machine
     * 3. merge_files(string gen_trace_dir): merge the file with format "/ptrace-" and put them into the "gen_trace_dir"
     * 4. hotspot_probe: probing the hotspot
     * 5. hotspot_prepare: prepare the hotspot from a reference file. bool specify whether to mutate the hot area
     * 6. vector<b_rule> gen_seed_hotspot(size_t prepair_no, size_t max_rule): generate seed hotspot for evolving
     * 7. vector<b_rule> evolve_patter(const vector<b_rule> & seed): evolve the seed and generate new hotspots
     * 8. raw_snapshot(...): this takes a snapshot (file, start_time, interval, sample_time, whether_do_rule_check)
     * 9.raw_hp_similarity(...): this calculates the host-pair similarity among different periods.
     */
    void trace_get_ts(string);
    friend uint32_t count_proc();
    void merge_files(string) const;
    void hotspot_probe(string);  // TODO: need para setting
    void hotspot_prepare();
    vector<b_rule> gen_seed_hotspot(size_t, size_t);
    vector<b_rule> evolve_pattern(const vector<b_rule> &);
    void raw_snapshot(string, double, double);
    void pcap_snapshot(size_t, double, pref_addr = pref_addr(), pref_addr = pref_addr());
    void raw_hp_similarity(string, double, double, double, size_t = 10);

    /* trace generation and evaluation
     * 1. pFlow_pruning_gen(string trace_root_dir): generate traces to the root directory with "Trace_Generate" sub-dir
     * 2. flow_pruning_gen(string trace_dir): generate a specific trace with specific parameter
     * 3. f_pg_st(...): a single thread for mapping and generate traces
     * 4. flow_arr_mp(): obtain the start time of each flow for later use.
     * 5. f_arr_st(...): a single thread for counting the no. of packets for each flow
     * 6. parse_pack_file_mp(string): process the file from pcap directory and process them into 5tup file
     * 7. p_pf_st(vector<string>): obtain the pcap file in vector<string> and do it.
     * 8. packet_count_mp(...): count the packet of each flow...  // deprecated
     * 9. p_count_st(...): single thread method for packet_count... // deprecated
     */
    void pFlow_pruning_gen(bool);
    void flow_pruneGen_mp(unordered_set<addr_5tup> &) const;
    void flow_pruneGen_mp_ev(unordered_set<addr_5tup> &) const;
    void f_pg_st (string, uint32_t, boost::unordered_map<addr_5tup, std::pair<uint32_t, addr_5tup> > *) const;
    boost::unordered_set<addr_5tup> flow_arr_mp() const;
    boost::unordered_set<addr_5tup> f_arr_st (string) const;
    void parse_pcap_file_mp(size_t, size_t) const;
    void p_pf_st(vector<string>, size_t) const;

    void packet_count_mp(string, string);
    void p_count_st(fs::path, atomic_uint*, mutex *, boost::unordered_map<addr_5tup, uint32_t>*, atomic_bool *);
};


// pcap related
#define ETHER_ADDR_LEN	6
#define ETHER_TYPE_IP		(0x0800)
#define ETHER_TYPE_8021Q 	(0x8100)

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};


/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

#endif
