#include "OFswitch.h"
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
namespace fs = boost::filesystem;
namespace io = boost::iostreams;

using std::ifstream;
/* Constructor:
 *
 * method brief:
 */

OFswitch::OFswitch() {
    rList = NULL;
    bTree = NULL;

    mode = 0;
    simuT = 0;
    TCAMcap = 0;
    tracefile_str = "";
}

/* Constructor:
 *
 *
 * method brief:
 * same as default
 */
void OFswitch::set_para(string para_file, rule_list * rL, bucket_tree * bT) {
    ifstream ff(para_file);
    rList = rL;
    bTree = bT;
    
    cout << "configuring parameter file" << endl;

    for (string str; getline(ff, str); ) {
        vector<string> temp;
        boost::split(temp, str, boost::is_any_of(" \t"),
                boost::token_compress_on);
        if (!temp[0].compare("mode")) {
            mode = boost::lexical_cast<uint32_t>(temp[1]);
        }
        if (!temp[0].compare("simuT")) {
            simuT = boost::lexical_cast<double>(temp[1]);
        }
        if (!temp[0].compare("TCAMcap")) {
            TCAMcap = boost::lexical_cast<uint32_t>(temp[1]);
        }
        if (!temp[0].compare("tracefile_str")) {
            tracefile_str = temp[1];
        }
    }
}

/* run_test
 *
 * method brief:
 * do test according mode id
 * mode 0: CAB, mode 1: Exact Match, mode 2: Cache Dependent Rules, mode 3: Cache micro rules
 */

void OFswitch::run_test() {
    cout << "Processing Trace " << tracefile_str <<endl;
    switch (mode) {
    case 0:
        cout << "Running CAB..." << endl;
        CABtest_rt_TCAM();
        break;
    case 1:
        cout << "Running CEM..." << endl;
        CEMtest_rt_id();
        break;
    case 2:
        cout << "Running CDR..." << endl;
        CDRtest_rt();
        break;
    case 3:
        cout << "Running CMR..." << endl;
        CMRtest_rt();
        break;
    default:
        return;
    }
}

/* CABtest_rt_TCAM
 *
 * method brief:
 * test caching in bucket
 * trace format <addr5tup(easyRW)>
 * test CAB performance
 */
void OFswitch::CABtest_rt_TCAM() {
    double curT = 0;

    lru_cache_cab cam_cache(TCAMcap, simuT);
    boost::unordered_set<addr_5tup> flow_rec;

    try {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        ifstream infile(tracefile_str);
        in.push(infile);

        string str; // tune curT to that of first packet
        getline(in,str);
        addr_5tup first_packet(str);
        curT = first_packet.timestamp;

        while(getline(in, str)) {
            addr_5tup packet(str);
            curT = packet.timestamp;
            auto res = flow_rec.insert(packet);
            bucket* buck = bTree->search_bucket(packet, bTree->root).first;
            //++total_packet;
            if (buck!=NULL) {
                cam_cache.ins_rec(buck, curT, res.second);
            } else
                cout<<"null bucket" <<endl;

            if (curT > simuT)
                break;
        }
    } catch (const io::gzip_error & e) {
        cout<<e.what()<<endl;
    }

    cam_cache.fetch_data();
}

/* CEMtest_rt_id
 *
 * method brief:
 * testing cache exact match entries
 * trace format <time \t ID>
 * others same as CABtest_rt_TCAM
 */
void OFswitch::CEMtest_rt_id() {
    fs::path ref_trace_path(tracefile_str);
    if (!(fs::exists(ref_trace_path) && fs::is_regular_file(ref_trace_path))) {
        cout<<"Missing Ref file"<<endl;
        return;
    }

    double curT = 0;
    lru_cache<uint32_t> flow_table(TCAMcap, simuT);
    std::set<uint32_t> flow_rec;

    try {
        io::filtering_istream trace_stream;
        trace_stream.push(io::gzip_decompressor());
        ifstream trace_file(tracefile_str);
        trace_stream.push(trace_file);

        string str;

        while(getline(trace_stream, str)) {
            vector<string> temp;
            boost::split(temp, str, boost::is_any_of("\t"));
            curT = boost::lexical_cast<double> (temp[0]);
            uint32_t flow_id = boost::lexical_cast<uint32_t> (temp[1]);
            auto res = flow_rec.insert(flow_id);
            flow_table.ins_rec(flow_id, curT, res.second);

            if (curT > simuT)
                break;
        }
    } catch (const io::gzip_error & e) {
        cout<<e.what()<<endl;
    }

    flow_table.fetch_data();

}

/* CDRtest_rt
 *
 * method brief:
 * test caching all dependent rules
 * others same as CABtest_rt_TCAM
 */
void OFswitch::CDRtest_rt() {
    fs::path ref_trace_path(tracefile_str);
    if (!(fs::exists(ref_trace_path) && fs::is_regular_file(ref_trace_path))) {
        cout<<"Missing Ref file"<<endl;
        return;
    }

    lru_cache_cdr cam_cache(TCAMcap, simuT);
    boost::unordered_set<addr_5tup> processed_flow;

    double curT = 0;

    try {
        io::filtering_istream trace_stream;
        trace_stream.push(io::gzip_decompressor());
        ifstream trace_file(tracefile_str);
        trace_stream.push(trace_file);

        string str;
        while(getline(trace_stream, str)) {
            addr_5tup packet(str);
            curT = packet.timestamp;

            for (uint32_t idx = 0; idx < rList->list.size(); idx++) { // linear search
                if ((rList->list[idx]).packet_hit(packet)) {
                    auto res = processed_flow.insert(packet);
                    cam_cache.ins_rec(idx, curT, rList->dep_map[idx], res.second);
                    break;
                }
            }

            if (curT > simuT)
                break;
        }
    } catch (const io::gzip_error & e) {
        cout<<e.what()<<endl;
    }

    cam_cache.fetch_data();
}


void OFswitch::CMRtest_rt() {
    fs::path ref_trace_path(tracefile_str);
    if (!(fs::exists(ref_trace_path) && fs::is_regular_file(ref_trace_path))) {
        cout<<"Missing Ref file"<<endl;
        return;
    }

    double curT = 0;
    lru_cache<r_rule> cam_cache(TCAMcap, simuT);
    boost::unordered_set<addr_5tup> flow_rec;

    try {
        io::filtering_istream trace_stream;
        trace_stream.push(io::gzip_decompressor());
        ifstream trace_file(tracefile_str);
        trace_stream.push(trace_file);

        string str;
        while(getline(trace_stream, str)) {
            addr_5tup packet(str);
            curT = packet.timestamp;
            auto res = flow_rec.insert(packet);

            // r_rule mRule = rList->get_micro_rule(packet);
            r_rule mRule = rList->get_micro_rule_split(packet);
            cam_cache.ins_rec(mRule, curT, res.second);
            string str;
            if (curT > simuT)
                break;
        }
    } catch (const io::gzip_error & e) {
        cout<<e.what()<<endl;
    }
    cam_cache.fetch_data();
}
