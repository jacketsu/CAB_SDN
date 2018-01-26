#include "TraceAnalyze.h"

using std::string;
using std::ifstream;
using std::ofstream;
using std::cout;
using std::endl;
using std::set;

namespace fs = boost::filesystem;
namespace io = boost::iostreams;
void syn_trace_plot_hp(string tracefile, string output) {
    io::filtering_istream ref_trace_stream;
    ref_trace_stream.push(io::gzip_decompressor());
    ifstream ref_trace_file(tracefile);
    ref_trace_stream.push(ref_trace_file);
    boost::unordered_set<addr_5tup> flow_rec;
    set<uint32_t> header_rec;

    string str;
    getline(ref_trace_stream, str);
    //cout << str << endl;
    addr_5tup packet(str);
    double terminT = packet.timestamp + 600;
    double checkpoint = packet.timestamp + 60;

    while (getline(ref_trace_stream, str)) {
        addr_5tup packet(str);
        header_rec.insert(packet.addrs[0]);
        header_rec.insert(packet.addrs[1]);
        flow_rec.insert(packet);

        if (packet.timestamp > terminT)
            break;
        if (packet.timestamp > checkpoint) {
            checkpoint += 60;
            cout << "reached: " << checkpoint << endl;
        }
    }
    io::close(ref_trace_stream);

    ofstream ff(output);
    for (boost::unordered_set<addr_5tup>::iterator iter=flow_rec.begin(); iter != flow_rec.end(); iter++) {
        uint32_t src = distance(header_rec.begin(), header_rec.find(iter->addrs[0]));
        uint32_t dst = distance(header_rec.begin(), header_rec.find(iter->addrs[1]));
        ff<<src<<"\t"<<dst<<endl;
    }
    ff.close();
}

void syn_trace_measure(rule_list & rList, string tracefile, string unzip_file){
	io::filtering_istream ref_trace_stream;
	ref_trace_stream.push(io::gzip_decompressor());
	ifstream ref_trace_file(tracefile);
	ref_trace_stream.push(ref_trace_file);
	ofstream unzipped (unzip_file);
	
	boost::unordered_set<addr_5tup> flow_rec;

	for(string str; getline(ref_trace_stream, str); ){
		addr_5tup packet(str);
		if (packet.timestamp > 300)
			break;
		flow_rec.insert(packet);
		unzipped<<packet.str_readable()<<endl;
	}

	set <int> rule_hit_rec;
	for (auto iter = flow_rec.begin(); iter != flow_rec.end(); ++iter){
		int i = rList.linear_search(*iter);
		rule_hit_rec.insert(i);
	}

	cout << rule_hit_rec.size() << " out of " << rList.list.size() << " rules are hit"<<endl;
}
