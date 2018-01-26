#include "TraceGen.h"

using std::string;
using std::vector;
using std::pair;
using std::list;
using std::set;
using std::cout;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::stringstream;
using std::thread;
using std::atomic_uint;
using std::atomic_bool;
using std::mutex;
using boost::unordered_map;
using boost::unordered_set;
namespace fs = boost::filesystem;
namespace io = boost::iostreams;

typedef boost::unordered_map<addr_5tup, uint32_t>::iterator Map_iter;
typedef vector<fs::path> Path_Vec_T;

/* ---------------------------- tgen_para ----------------------- */
tgen_para::tgen_para() {
    /* default para settings */
    flow_rate = 100;
    simuT = 1800;

    cold_prob = 0;
    hot_rule_thres = 6;
    hot_candi_no = 40;
    hotspot_no = 10;
    hotvtime = 10;

    mut_scalar[0] = 4;
    mut_scalar[1] = 1;

    evolving = false;
    evolving_time = 20;
    evolving_no = 10;

    prep_mutate = false;

    flow_rate_step = 10; 
    cold_prob_step = 0;
    hotspot_no_step = 0;
}

tgen_para::tgen_para(const tgen_para & another_para) {
    this->simuT = another_para.simuT;
    this->flow_rate = another_para.flow_rate;
    this->cold_prob = another_para.cold_prob;
    this->hotcandi_str = another_para.hotcandi_str;
    this->hotspot_ref = another_para.hotspot_ref;

    for (int i = 0; i < 4; ++i)
        this->scope[i] = another_para.scope[i];

    this->mut_scalar[0] = another_para.mut_scalar[0];
    this->mut_scalar[1] = another_para.mut_scalar[1];

    this->prep_mutate = another_para.prep_mutate;

    this->hot_rule_thres = another_para.hot_rule_thres;
    this->hot_candi_no = another_para.hot_candi_no;

    this->hotvtime = another_para.hotvtime;
    this->evolving_time = another_para.evolving_time;
    this->evolving_no = another_para.evolving_no;

    this->trace_root_dir = another_para.trace_root_dir;
    this->flowInfoFile_str = another_para.flowInfoFile_str;
    this->pcap_dir = another_para.pcap_dir;
    this->parsed_pcap_dir = another_para.parsed_pcap_dir;
}

tgen_para::tgen_para(string config_file):tgen_para() {
    /* read config file */
    ifstream config_stream(config_file);
    string config_line;

    while (getline(config_stream, config_line)) {
        vector<string> tmp_arr;
        boost::split(tmp_arr, config_line, boost::is_any_of(" \t"),
                     boost::token_compress_on);

        if (tmp_arr.size() >= 2) {
            /* this is a comment */
            if (tmp_arr[0][0] == '#')
                continue;

            if (tmp_arr[0] == "gen_root_dir") {
                trace_root_dir = tmp_arr[1];
                continue;
            }

            if (tmp_arr[0] == "meta_dir") {
                flowInfoFile_str = tmp_arr[1] + "/flow_info";
                hotcandi_str = tmp_arr[1] + "/hotspot.dat";
                hotspot_ref = tmp_arr[1] + "/tree_pr.dat";
                continue;
            }

            if (tmp_arr[0] == "flow_arrival_rate") {
                flow_rate = boost::lexical_cast<double>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "trace_len") {
                simuT = boost::lexical_cast<double>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "cold_probability") {
                cold_prob = boost::lexical_cast<double>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "hotspot_number") {
                hotspot_no = boost::lexical_cast<uint32_t>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "scope" && tmp_arr.size() >= 5) {
                for(int i = 0; i < 4; ++i) {
                    scope[i] = boost::lexical_cast<uint32_t>(tmp_arr[i+1]);
                }
                continue;
            }

            if (tmp_arr[0] == "mutate_scale" && tmp_arr.size() >= 3) {
                for (int i = 0; i < 2; ++i) {
                    mut_scalar[i] = boost::lexical_cast<uint32_t>(tmp_arr[i+1]);
                }
                continue;
            }

            if (tmp_arr[0] == "mutate_at_hot_prep") {
                if (tmp_arr[1] == "true")
                    prep_mutate = true;
                continue;
            }

            if (tmp_arr[0] == "hot_rule_size_thres") {
                hot_rule_thres = boost::lexical_cast<uint32_t>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "hotspot_candidate_no") {
                hot_candi_no = boost::lexical_cast<uint32_t>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "hotspot_arrival_time") {
                hotvtime = boost::lexical_cast<double>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "evolving") {
                if (tmp_arr[1] == "true")
                    evolving = true;
            }
            if (tmp_arr[0] == "evolving_time") {
                evolving_time = boost::lexical_cast<double>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "evolving_no") {
                evolving_no = boost::lexical_cast<size_t>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "origin_trace_dir") {
                pcap_dir = tmp_arr[1];
                continue;
            }

            if (tmp_arr[0] == "parsed_origin_trace_dir") {
                parsed_pcap_dir = tmp_arr[1];
                continue;
            }

            if (tmp_arr[0] == "bulk_no") {
                bulk_no = boost::lexical_cast<int>(tmp_arr[1]);
                continue;
            }

            if (tmp_arr[0] == "flow_rate_step") {
                flow_rate_step = boost::lexical_cast<int>(tmp_arr[1]);
                continue;  
            }

            if (tmp_arr[0] == "cold_prob_step") {
                cold_prob_step = boost::lexical_cast<double>(tmp_arr[1]);
                continue;  
            }

            if (tmp_arr[0] == "hotspot_no_step") {
                hotspot_no_step = boost::lexical_cast<int>(tmp_arr[1]);
                continue;  
            }
        }
    }
}

/* tracer
 *
 * function brief:
 * constructor: set rule list and simulation time offset
 */
tracer::tracer():total_packet(0) {
    rList = NULL;
    flow_no = 0;
    jesusBorn = EpochT(-1,0);
    para = tgen_para();
}

tracer::tracer(rule_list * rL, string para_file):total_packet(0) {
    para = tgen_para(para_file);
    rList = rL;
    flow_no = 0;
    jesusBorn = EpochT(-1,0);

    this->para = para;
}

void tracer::print_setup() const {
    cout <<" ======= SETUP BRIEF: ======="<< endl;
    cout <<"(basic)"<<endl;
    cout <<"Avg flow arrival rate:\t\t"<<para.flow_rate<<endl;
    cout <<"Trace length:\t\t\t"<<para.simuT<<" sec"<<endl;
    cout <<"(locality)"<<endl;
    cout <<"Cold trace probability: \t"<<para.cold_prob <<endl;
    cout <<"Hot spot no: \t\t\t"<<para.hotspot_no <<endl;
    cout <<"Scope: \t\t\t\t"<<para.scope[0]<<":"<<para.scope[1];
    cout <<":"<<para.scope[2] << ":"<<para.scope[3]<<endl;
    cout <<"Mutate scaling parameter:\t"<<para.mut_scalar[0]<<":"<<para.mut_scalar[1]<<endl;
    cout <<"Mutate preparation: \t\t"<<para.prep_mutate<<endl;
    cout <<"Thres size for a hot rule: \t"<<para.hot_rule_thres<<endl;
    cout <<"No. of hot rule candidates: \t"<<para.hot_candi_no<<endl;
    cout <<"(dirs)"<<endl;
    cout <<"flow arrival info: \t\t" << para.flowInfoFile_str << endl;
    cout <<"hotspot candidates are in\t" << para.hotcandi_str<<endl;
    cout <<"parsed real trace: \t\t" << para.parsed_pcap_dir<<endl;
    cout <<"original real trace: \t\t" << para.pcap_dir<<endl;
    cout <<" =========== END ==========="<<endl;
}

/* trace_get_ts
 *
 * input: string trace_ts_file: the timestamp output for each file
 *
 * function brief:
 * 	  outputs the first packet timestamp of each trace file, helps determine how many trace files to use
 */
void tracer::trace_get_ts(string trace_ts_file) {
    fs::path dir(para.parsed_pcap_dir);
    ofstream ffo(trace_ts_file);
    if (fs::exists(dir) && fs::is_directory(dir)) {
        Path_Vec_T pvec;
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());

        //for (fs::directory_iterator iter(dir); (iter != end); ++iter) {
        for (Path_Vec_T::const_iterator it (pvec.begin()); it != pvec.end(); ++it) {
            try {
                io::filtering_istream in;
                in.push(io::gzip_decompressor());
                ifstream infile(it->c_str());
                in.push(infile);
                string str;
                getline(in, str);
                addr_5tup f_packet(str);
                ffo<< *it << "\t" << f_packet.timestamp <<endl;
                io::close(in); // careful
            } catch (const io::gzip_error & e) {
                cout<<e.what()<<std::endl;
            }
        }
    }
    return;
}

/* get_proc_file
 *
 * input: string ref_trace_dir: real trace directory
 * output:vector <fs::ps> :     paths of the real trace files in need for process
 *
 * function_brief:
 * get the paths of real traces within the range of the simulation Time
 */
void tracer::get_proc_files () {
    // find out how many files to process
    fs::path dir(para.parsed_pcap_dir);

    if (fs::exists(dir) && fs::is_directory(dir)) {
        Path_Vec_T pvec;
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());

        for (Path_Vec_T::const_iterator it (pvec.begin()); it != pvec.end(); ++it) {
            try {
                io::filtering_istream in;
                in.push(io::gzip_decompressor());
                ifstream infile(it->c_str());
                in.push(infile);
                string str;
                getline(in,str);

                if (jesusBorn < 0) { // init jesusBorn
                    EpochT time (str);
                    jesusBorn = time;
                }

                addr_5tup packet(str, jesusBorn); // readable

                if (packet.timestamp > para.simuT) {
                    io::close(in);
                    break;
                }

                to_proc_files.push_back(it->string());
                io::close(in);
            } catch(const io::gzip_error & e) {
                cout<<e.what()<<endl;
            }
        }
    }
}

/* count_proc
 *
 * output: uint32_t: the count no. of processors, helps determine thread no.
 */
uint32_t count_proc() {
    ifstream infile ("/proc/cpuinfo");
    uint32_t counter = 0;
    for (string str; getline(infile,str); )
        if (str.find("processor\t") != string::npos)
            counter++;
    return counter;
}

/* merge_files
 *
 * input: string gen_trace_dir: the targetting dir
 *
 * function_brief:
 * Collects the gz traces with prefix "ptrace-";
 * Merge into one gz trace named "ref_trace.gz"
 */
void tracer::merge_files(string proc_dir) const {
    fs::path file (proc_dir + "/ref_trace.gz");
    if (fs::exists(file))
        fs::remove(file);

    for (uint32_t i = 0; ; ++i) {
        stringstream ss;
        ss<<proc_dir<<"/ptrace-";
        ss<<std::setw(3)<<std::setfill('0')<<i;
        ss<<".gz";
        fs::path to_merge(ss.str());
        if (fs::exists(to_merge)) {
            io::filtering_ostream out;
            out.push(io::gzip_compressor());
            ofstream out_file(proc_dir+"/ref_trace.gz", std::ios_base::app);
            out.push(out_file);
            cout << "Merging:" << ss.str()<<endl;
            io::filtering_istream in;
            in.push(io::gzip_decompressor());
            ifstream in_file(ss.str().c_str());
            in.push(in_file);
            io::copy(in, out);
            in.pop();
            fs::remove(to_merge);
            out.pop();
        } else
            break;
    }
}

/* hotspot_prob
 *
 * input: string sav_str: output file path
 *
 * function brief:
 * probe and generate the hotspot candidate and put them into a candidate file for later header mapping
 */
void tracer::hotspot_probe(string sav_str) {
    uint32_t hs_count = 0;
    ofstream ff (sav_str);
    uint32_t probe_scope[4];
    uint32_t trial = 0;
    while (hs_count < para.hot_candi_no) {
        vector<p_rule>::iterator iter = rList->list.begin();
        advance (iter, rand() % rList->list.size());
        // cout<< "candi rule:" << iter->get_str() << endl;
        addr_5tup probe_center = iter->get_random();

        for (uint32_t i=0; i<4; i++)
            probe_scope[i] = para.scope[i]/2 + rand() % para.scope[i];

        h_rule hr (probe_center, probe_scope);
        cout << hr.get_str() << "\t" << hr.cal_rela(rList->list) << endl;

        if (hr.cal_rela(rList->list) >= para.hot_rule_thres) {
            ff << probe_center.str_easy_RW() << "\t" << probe_scope[0] << ":"
               << probe_scope[1] << ":" << probe_scope[2] << ":" <<
               probe_scope[3] << endl;
            trial = 0;
            ++hs_count;
        }

        ++trial;

        if (trial > 100) {
            cout<<"change para setting"<<endl;
            return;
        }
    }
    ff.close();
}

/* hotspot_prob
 *
 * input: string sav_str: output file path
 *
 * function brief:
 * generate the hotspot candidate with some reference file and put them into a candidate file for later header mapping
 */
void tracer::hotspot_prepare() {
    uint32_t hs_count = 0;

    ofstream ff (para.hotcandi_str);
    vector <string> file;
    ifstream in (para.hotspot_ref);

    if (para.prep_mutate)
        cout <<"mutation scalar " << para.mut_scalar[0] << " " << para.mut_scalar[1] << endl;

    for (string str; getline(in, str); ) {
        vector<string> temp;
        boost::split(temp, str, boost::is_any_of("\t"));
        if (boost::lexical_cast<uint32_t>(temp.back()) > para.hot_rule_thres) {
            if (para.prep_mutate) {
                b_rule br(str);
                br.mutate_pred(para.mut_scalar[0], para.mut_scalar[1]);
                str = br.get_str();
                size_t assoc_no = 0;
                for (auto iter = rList->list.begin(); iter != rList->list.end(); ++iter)
                    if (br.match_rule(*iter))
                        ++assoc_no;
                stringstream ss;
                ss << str << "\t" << assoc_no;
                str = ss.str();
            }
            file.push_back(str);
        }
    }

    random_shuffle(file.begin(), file.end());
    vector<string>::iterator iter = file.begin();

    while (hs_count < para.hot_candi_no && iter < file.end()) {
        ff <<*iter<<endl;
        iter++;
        ++hs_count;
    }

    ff.close();
}


vector<b_rule> tracer::gen_seed_hotspot(size_t prepare_no, size_t max_rule) {
    vector<b_rule> gen_traf_block;
    ifstream in (para.hotspot_ref);
    for (string str; getline(in, str); ) {
        vector<string> temp;
        boost::split(temp, str, boost::is_any_of("\t"));
        if (boost::lexical_cast<uint32_t>(temp.back()) > para.hot_rule_thres) {
            b_rule br(str);
            size_t assoc_no = 0;
            for (auto iter = rList->list.begin(); iter != rList->list.end(); ++iter) {
                if (br.match_rule(*iter)) {
                    ++assoc_no;
                }
            }
            if (assoc_no > max_rule)
                continue;

            gen_traf_block.push_back(br);
        }
    }
    random_shuffle(gen_traf_block.begin(), gen_traf_block.end());
    if (prepare_no > gen_traf_block.size())
        prepare_no = gen_traf_block.size();
    gen_traf_block.resize(prepare_no);
    return gen_traf_block;
}

vector<b_rule> tracer::evolve_pattern(const vector<b_rule> & seed_hot_spot) {
    vector<b_rule> gen_traf_block;
    for (auto iter = seed_hot_spot.begin(); iter != seed_hot_spot.end(); ++iter) {
        b_rule to_push = *iter;
        to_push.mutate_pred(para.mut_scalar[0], para.mut_scalar[1]);
        gen_traf_block.push_back(to_push);
    }
    return gen_traf_block;
}

void tracer::raw_snapshot(string tracedir, double start_time, double interval) {
    fs::path dir(tracedir);

    Path_Vec_T pvec;
    if (fs::exists(dir) && fs::is_directory(dir)) {
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());
    } else
        return;

    EpochT jesusBorn(-1,0);

    boost::unordered_map<pair<size_t, size_t>, size_t> hostpair_rec;
    set<size_t> hosts;

    bool stop = false;
    bool start_processing = false;

    for (Path_Vec_T::const_iterator it (pvec.begin()); it != pvec.end() && !stop; ++it) {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        ifstream infile(it->c_str());
        in.push(infile);
        string str;
        getline(in, str);

        if (jesusBorn < 0) {
            jesusBorn = EpochT(str);
        }
        if (EpochT(str) < jesusBorn + start_time) {
            if ( it+1 != pvec.end() )
                continue;
        } else if (!start_processing) {
            --it;
            start_processing = true;
        }

        cout << "processing" << it->c_str() << endl;

        in.pop();
        infile.close();
        infile.open(it->c_str());
        in.push(infile);

        for (string str; getline(in, str); ) {
            addr_5tup packet (str, jesusBorn);
            if (packet.timestamp < start_time + interval) {
                auto key = std::make_pair(packet.addrs[0], packet.addrs[1]);
                auto res = hostpair_rec.insert(std::make_pair(key, 1));
                hosts.insert(packet.addrs[0]);
                hosts.insert(packet.addrs[1]);
                if (!res.second)
                    ++hostpair_rec[key];
            } else {
                stop = true;
                break;
            }
        }
    }

    cout << "total host no: "<< hosts.size()<<endl;
    cout << "total hostpair no: "<< hostpair_rec.size() <<endl;


    ofstream ff("snapshot.dat");
    for ( auto it = hostpair_rec.begin(); it != hostpair_rec.end(); ++it) {
        int x_dist = std::distance(hosts.begin(), hosts.find(it->first.first));
        int y_dist = std::distance(hosts.begin(), hosts.find(it->first.second));
        ff<<x_dist<<"\t"<<y_dist<<"\t"<<it->second<<endl;
    }
}

void tracer::pcap_snapshot(size_t file_st, double interval, pref_addr src_subnet, pref_addr dst_subnet) {
    fs::path dir(para.pcap_dir);
    jesusBorn = EpochT(-1,0);

    boost::unordered_map<pair<size_t, size_t>, size_t> hostpair_rec;
    set<size_t> hosts;
    bool stop = false;

    if (fs::exists(dir) && fs::is_directory(dir)) {
        Path_Vec_T pvec;
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());

        for (auto it = pvec.begin()+file_st; !stop && it != pvec.end(); ++it) {

            struct pcap_pkthdr header; // The header that pcap gives us
            const u_char *packet; // The actual packet
            pcap_t *handle;
            const struct sniff_ethernet * ethernet;
            const struct sniff_ip * ip;
            const struct sniff_tcp *tcp;
            uint32_t size_ip;
            uint32_t size_tcp;
            char errbuf[PCAP_ERRBUF_SIZE];

            handle = pcap_open_offline(it->c_str(), errbuf);

            while (true) {
                packet = pcap_next(handle, &header);
                if (packet == NULL)
                    break;
                ethernet = (struct sniff_ethernet*)(packet);

                int ether_offset = 0;
                if (ntohs(ethernet->ether_type) == ETHER_TYPE_IP) {
                    ether_offset = 14;
                } else if (ntohs(ethernet->ether_type) == ETHER_TYPE_8021Q) {
                    // here may have a bug
                    ether_offset = 18;
                } else {
                    continue;
                }

                ip = (struct sniff_ip*)(packet + ether_offset);

                size_ip = IP_HL(ip)*4;
                if (IP_V(ip) != 4 || size_ip < 20)
                    continue;
                if (uint32_t(ip->ip_p) != 6)
                    continue;

                tcp = (struct sniff_tcp*)(packet + ether_offset + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                if (size_tcp < 20)
                    continue;

                if (jesusBorn < 0)
                    jesusBorn = EpochT(header.ts.tv_sec, header.ts.tv_usec);

                EpochT cur_ts(header.ts.tv_sec, header.ts.tv_usec);
                if (cur_ts.toDouble(jesusBorn) > interval) {
                    stop = true;
                    break;
                }

                uint32_t ip_src = ntohl(ip->ip_src.s_addr);
                uint32_t ip_dst = ntohl(ip->ip_dst.s_addr);

                if (!(src_subnet.hit(ip_src) && dst_subnet.hit(ip_dst)))
                    continue;
                auto key = std::make_pair(ip_src, ip_dst);
                auto res = hostpair_rec.insert(std::make_pair(key, 1));
                hosts.insert(ip_src);
                hosts.insert(ip_dst);
                if (!res.second)
                    ++hostpair_rec[key];
            }
            pcap_close(handle);
            cout << "finished_processing : "<< it->c_str() << endl;
        }
    }

    stringstream ss;
    ss << "snapshot-"<<file_st<<".dat";
    ofstream ff(ss.str());
    ofstream ff1("hostpair");

    for ( auto it = hosts.begin(); it != hosts.end(); ++it) {
        ff1 << *it << endl;
    }

    for ( auto it = hostpair_rec.begin(); it != hostpair_rec.end(); ++it) {
        int x_dist = std::distance(hosts.begin(), hosts.find(it->first.first));
        int y_dist = std::distance(hosts.begin(), hosts.find(it->first.second));
        ff<<x_dist<<"\t"<<y_dist<<"\t"<<it->second<<endl;
    }

    cout << "Finished Plotting.. " <<endl;

}

const uint32_t mask_C = ((~uint32_t(0)) << 4);
struct hostpair {
    uint32_t pairs[2];

    hostpair() {
        pairs[0] = 0;
        pairs[1] = 0;
    }

    //hostpair(uint32_t i, uint32_t j){pairs[0] = i & mask_C; pairs[1] = j & mask_C;}
    hostpair(uint32_t i, uint32_t j) {
        pairs[0] = i ;
        pairs[1] = j;
    }
    hostpair(const hostpair & hp) {
        pairs[0] = hp.pairs[0];
        pairs[1] = hp.pairs[1];
    }

    bool operator ==(const hostpair & rhs) const {
        return (pairs[0] == rhs.pairs[0] && pairs[1] == rhs.pairs[1]);
    }

    friend size_t hash_value(hostpair const & rhs) {
        size_t seed = 0;
        boost::hash_combine(seed, rhs.pairs[0]);
        boost::hash_combine(seed, rhs.pairs[1]);
        return seed;
    }

};

bool cmp(const hostpair & lhs, const hostpair & rhs) {
    if (lhs.pairs[0] < rhs.pairs[0])
        return true;
    if (lhs.pairs[0] == rhs.pairs[0] && lhs.pairs[1] < rhs.pairs[1])
        return true;
    return false;
}

void tracer::raw_hp_similarity(string tracedir, double measure_len, double duration, double interval, size_t sampling_time) {
    int data_no = measure_len/interval;
    vector<double> stat(data_no, 0);

    fs::path dir(tracedir);

    Path_Vec_T pvec;
    if (fs::exists(dir) && fs::is_directory(dir)) {
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());
    } else
        return;

    EpochT jesusBorn(-1,0);

    if (duration > interval)
        interval = duration;

    vector< vector<hostpair> > buffer;
    double next_checkpoint = duration;
    bool samp_wait = true;
    size_t to_sample = sampling_time;

    unordered_map<hostpair, size_t> recorder;

    for (Path_Vec_T::const_iterator it (pvec.begin()); it != pvec.end() && (to_sample != 0); ++it) {
        BOOST_LOG(tracer_log) << "processing" << it->c_str();
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        ifstream infile(it->c_str());
        in.push(infile);
        string str;

        if (jesusBorn < 0) {
            getline(in, str);
            jesusBorn = EpochT(str);
        }

        for (string str; getline(in, str) && (to_sample != 0); ) {
            addr_5tup packet(str, jesusBorn);
            if (samp_wait) {
                if (packet.timestamp > next_checkpoint) {
                    samp_wait = false;
                    next_checkpoint += interval-duration;
                    vector<hostpair> hp_snapshot;

                    for (auto iter = recorder.begin(); iter != recorder.end(); ++iter) {
                        if (iter->second <= 10)
                            continue;
                        hp_snapshot.push_back(iter->first);
                        std::sort(hp_snapshot.begin(), hp_snapshot.end(), cmp);
                    }
                    buffer.push_back(hp_snapshot);

                    if (buffer.size() == data_no+1) { // cal diff
                        BOOST_LOG(tracer_log) << "calculate ";
                        size_t counter = 0;
                        vector <hostpair> intersec = *buffer.begin();
                        for (auto iter = buffer.begin()+1; iter != buffer.end(); iter++) {
                            vector<hostpair> res_intersec;
                            //vector<hostpair> diff;
                            vector<hostpair> unio;
                            std::set_intersection(intersec.begin(), intersec.end(),
                                                  iter->begin(), iter->end(),
                                                  std::back_inserter(res_intersec),
                                                  cmp);
                            //std::set_difference(buffer.begin()->begin(), buffer.begin()->end(),
                            //		iter->begin(), iter->end(), std::back_inserter(diff),
                            //		cmp);
                            std::set_union(buffer.begin()->begin(), buffer.begin()->end(),
                                           iter->begin(), iter->end(), std::back_inserter(unio),
                                           cmp);
                            //BOOST_LOG(tracer_log) << diff.size() << "\t " << unio.size() ;
                            BOOST_LOG(tracer_log) << res_intersec.size() << "\t "<<unio.size();
                            //stat[counter] += double(diff.size())/double(unio.size());
                            stat[counter] += double(res_intersec.size())/double(unio.size());
                            intersec = res_intersec;
                            ++counter;
                        }
                        buffer.erase(buffer.begin());
                        --to_sample;
                        BOOST_LOG(tracer_log) << to_sample << " more";
                    }

                    recorder.clear();
                }
                hostpair hp(packet.addrs[0], packet.addrs[1]);
                auto res = recorder.insert(std::make_pair(hp, 1));
                if (!res.second)
                    ++recorder[hp];
            } else {
                if (packet.timestamp > next_checkpoint) {
                    samp_wait = true;
                    next_checkpoint += duration;
                }
            }
        }
    }
    ofstream ff ("similarity.dat");
    double dist = 0;
    for (auto iter = stat.begin(); iter != stat.end(); ++iter) {
        dist += interval;
        ff << dist <<"\t"<< *iter/sampling_time<<endl;
    }
}

// ===================================== Trace Generation and Evaluation =========================

/* pFlow_pruning_gen
 *
 * input: string trace_root_dir: target directory
 *
 * function_brief:
 * wrapper function for generate localized traces
 */
void tracer::pFlow_pruning_gen(bool evolving) {
    // init processing file
    if (to_proc_files.size() == 0) {
        get_proc_files();
    }

    // create root dir
    fs::path dir(para.trace_root_dir);
    if (fs::create_directory(dir)) {
        cout<<"creating: " << dir.string()<<endl;
    } else {
        cout<<"exitst: "<<dir.string()<<endl;
    }

    /* get the arrival time of each flow. */
    cout << "Generating flow arrival file ... ..."<<endl;
    unordered_set<addr_5tup> flowInfo;
    if (fs::exists(fs::path(para.flowInfoFile_str))) {
        ifstream infile(para.flowInfoFile_str.c_str());
        for (string str; getline(infile, str);) {
            addr_5tup packet(str);
            if (packet.timestamp > para.simuT)
                continue;
            flowInfo.insert(packet);
        }
        infile.close();
        cout << "Warning: using old flowInfo file" <<endl;
    } else {
        flowInfo = flow_arr_mp();
        cout << "flowInfo file generated" <<endl;
    }

    // trace generated in format of  "trace-200k-0.05-20"
    stringstream ss;
    ss<<dir.string()<<"/trace-"<<para.flow_rate<<"k-"<<para.cold_prob<<"-"<<para.hotspot_no;
    gen_trace_dir = ss.str();

    if (evolving)
        flow_pruneGen_mp_ev(flowInfo);
    else
        flow_pruneGen_mp(flowInfo);
}


/* flow_pruneGen_mp
 * input: unordered_set<addr_5tup> & flowInfo : first packet count
 * 	  string ref_trace_dir : real trace directory
 * 	  string hotspot_candi : candidate hotspot no. generated
 *
 * function_brief:
 * prune the headers according arrival, and map the headers
 */
void tracer::flow_pruneGen_mp( unordered_set<addr_5tup> & flowInfo) const {
    if (fs::create_directory(fs::path(gen_trace_dir)))
        cout<<"creating: "<<gen_trace_dir<<endl;
    else
        cout<<"exists:   "<<gen_trace_dir<<endl;

    std::multimap<double, addr_5tup> ts_prune_map;
    for (unordered_set<addr_5tup>::iterator iter=flowInfo.begin();
            iter != flowInfo.end(); ++iter) {
        ts_prune_map.insert(std::make_pair(iter->timestamp, *iter));
    }
    cout << "total flow no. : " << ts_prune_map.size() <<endl;

    /* prepare hot spots */
    list<h_rule> hotspot_queue;
    ifstream in (para.hotcandi_str);

    for (uint32_t i = 0; i < para.hotspot_no; i++) {
        string line;
        if (!getline(in, line)) {
            in.clear();
            in.seekg(0, std::ios::beg);
        }
        h_rule hr(line, rList->list);
        hotspot_queue.push_back(hr);
    }

    /* every ten second tube pruning eccessive flows */
    boost::unordered_map<addr_5tup, pair<uint32_t, addr_5tup> > pruned_map;

    /* pruned_map   old_header-> (header_id, new_header) */

    const double smoothing_interval = 10.0;
    double next_checkpoint = smoothing_interval;
    double flow_thres = 10 * para.flow_rate;

    vector< addr_5tup > header_buf;
    header_buf.reserve(3000);
    uint32_t id = 0;
    uint32_t total_header = 0;

    double nextKickOut = para.hotvtime;

    for (auto iter = ts_prune_map.begin(); iter != ts_prune_map.end(); ++iter) {
        if (iter->first > next_checkpoint) {
            random_shuffle(header_buf.begin(), header_buf.end());
            uint32_t i = 0;

            for (i = 0; i < flow_thres && i < header_buf.size(); ++i) {
                addr_5tup header;

                if ((double) rand()/RAND_MAX < (1-para.cold_prob)) {
                    /* hot packets */
                    auto q_iter = hotspot_queue.begin();
                    advance(q_iter, rand() % para.hotspot_no);
                    header = q_iter->gen_header();
                } else {
                    /* cold packets */
                    header = rList->list[(rand()%(rList->list.size()))].get_random();
                }

                pruned_map.insert(std::make_pair(header_buf[i], std::make_pair(id, header)));

                ++id;
            }

            total_header += i;
            header_buf.clear();
            next_checkpoint += smoothing_interval;
        }

        header_buf.push_back(iter->second);

        if (iter->first > nextKickOut) {
            hotspot_queue.pop_front();
            string line;
            if (!getline(in, line)) {
                in.clear();
                in.seekg(0, std::ios::beg);
                getline(in, line);
            }
            h_rule hr (line, rList->list);
            hotspot_queue.push_back(hr);
            nextKickOut += para.hotvtime;
        }
    }

    cout << "after smoothing, average: " << double(total_header)/para.simuT <<endl;

    /* process using multi-thread; */
    fs::path temp1(gen_trace_dir+"/IDtrace");
    fs::create_directory(temp1);
    fs::path temp2(gen_trace_dir+"/GENtrace");
    fs::create_directory(temp2);

    vector< std::future<void> > results_exp;

    for(uint32_t file_id = 0; file_id < to_proc_files.size(); ++file_id) {
        results_exp.push_back(std::async(std::launch::async,
                                         &tracer::f_pg_st, this,
                                         to_proc_files[file_id],
                                         file_id, &pruned_map));
    }

    for (uint32_t file_id = 0; file_id < to_proc_files.size(); ++file_id) {
        results_exp[file_id].get();
    }

    cout<< "Merging Files... "<<endl;
    merge_files(gen_trace_dir+"/IDtrace");
    merge_files(gen_trace_dir+"/GENtrace");

    cout<<"Generation Finished. Enjoy :)" << endl;
    return;
}

void tracer::flow_pruneGen_mp_ev( unordered_set<addr_5tup> & flowInfo) const {
    if (fs::create_directory(fs::path(gen_trace_dir)))
        cout<<"creating: "<<gen_trace_dir<<endl;
    else
        cout<<"exists:   "<<gen_trace_dir<<endl;

    std::multimap<double, addr_5tup> ts_prune_map;
    for (unordered_set<addr_5tup>::iterator iter=flowInfo.begin(); iter != flowInfo.end(); ++iter) {
        ts_prune_map.insert(std::make_pair(iter->timestamp, *iter));
    }
    cout << "total flow no. : " << ts_prune_map.size() <<endl;

    // prepair hot spots
    vector<h_rule> hotspot_seed;
    ifstream in (para.hotcandi_str);

    for (string str; getline(in, str); ) {
        vector<string> temp;
        boost::split(temp, str, boost::is_any_of("\t"));

        if (boost::lexical_cast<uint32_t>(temp.back()) > para.hot_rule_thres) {
            h_rule hr(str, rList->list);
            hotspot_seed.push_back(hr);
        }
    }

    random_shuffle(hotspot_seed.begin(), hotspot_seed.end());
    if (para.hot_candi_no > hotspot_seed.size()) {
        cout<<"revert to: " << hotspot_seed.size() << " hotspots"<<endl;
    } else {
        hotspot_seed = vector<h_rule>(hotspot_seed.begin(), hotspot_seed.begin()+ para.hot_candi_no);
    }
    vector<h_rule> hotspot_vec;

    for (auto iter = hotspot_seed.begin(); iter != hotspot_seed.end(); ++iter) {
        h_rule hr = *iter;
        hr.mutate_pred(para.mut_scalar[0], para.mut_scalar[1]);
        hotspot_vec.push_back(hr);
    }

    list<h_rule> hotspot_queue;
    auto cur_hot_iter = hotspot_vec.begin() + para.hotspot_no;
    for (size_t i = 0; i < para.hotspot_no; i++) {
        h_rule hr = hotspot_vec[i];
        hotspot_queue.push_back(hr);
    }

    // smoothing every 10 sec, map the headers
    boost::unordered_map<addr_5tup, pair<uint32_t, addr_5tup> > pruned_map;
    const double smoothing_interval = 10.0;
    double next_checkpoint = smoothing_interval;
    double flow_thres = 10 * para.flow_rate;
    vector< addr_5tup > header_buf;
    header_buf.reserve(3000);
    uint32_t id = 0;
    uint32_t total_header = 0;
    double nextKickOut = para.hotvtime;
    double nextEvolving = para.evolving_time;

    for (auto iter = ts_prune_map.begin(); iter != ts_prune_map.end(); ++iter) {
        if (iter->first > next_checkpoint) {
            random_shuffle(header_buf.begin(), header_buf.end());
            uint32_t i = 0 ;
            for (i = 0; i < flow_thres && i < header_buf.size(); ++i) {
                addr_5tup header;
                if ((double) rand() /RAND_MAX < (1-para.cold_prob)) { // no noise
                    auto q_iter = hotspot_queue.begin();
                    advance(q_iter, rand()%para.hotspot_no);
                    header = q_iter->gen_header();
                } else {
                    header = rList->list[(rand()%(rList->list.size()))].get_random();
                }
                pruned_map.insert( std::make_pair(header_buf[i], std::make_pair(id, header)));
                ++id;
            }
            total_header += i;
            header_buf.clear();
            next_checkpoint += smoothing_interval;
        }
        header_buf.push_back(iter->second);

        if (iter->first > nextKickOut) {
            hotspot_queue.pop_front();
            if (cur_hot_iter == hotspot_vec.end())
                cur_hot_iter = hotspot_vec.begin();
            hotspot_queue.push_back(*cur_hot_iter);
            ++cur_hot_iter;
            nextKickOut += para.hotvtime;
        }

        if (iter->first > nextEvolving) {
            vector<int> choice;
            for (int i = 0; i < hotspot_vec.size(); ++i)
                choice.push_back(i);
            random_shuffle(choice.begin(), choice.end());
            for (int i = 0; i < para.evolving_no; ++i) {
                h_rule hr = hotspot_seed[choice[i]];
                hr.mutate_pred(para.mut_scalar[0], para.mut_scalar[1]);
                hotspot_vec[choice[i]] = hr;
            }
            nextEvolving += para.evolving_time;
        }
    }
    cout << "after smoothing, average: " << double(total_header)/para.simuT <<endl;

    // process using multi-thread;
    fs::path temp1(gen_trace_dir+"/IDtrace");
    fs::create_directory(temp1);
    fs::path temp2(gen_trace_dir+"/GENtrace");
    fs::create_directory(temp2);


    vector< std::future<void> > results_exp;

    for(uint32_t file_id = 0; file_id < to_proc_files.size(); ++file_id) {
        results_exp.push_back(std::async(std::launch::async, &tracer::f_pg_st, this, to_proc_files[file_id], file_id, &pruned_map));
    }

    for (uint32_t file_id = 0; file_id < to_proc_files.size(); ++file_id) {
        results_exp[file_id].get();
    }

    cout<< "Merging Files... "<<endl;
    merge_files(gen_trace_dir+"/IDtrace");
    merge_files(gen_trace_dir+"/GENtrace");

    cout<<"Generation Finished. Enjoy :)" << endl;
    return;
}

void tracer::f_pg_st(string ref_file, uint32_t id, boost::unordered_map<addr_5tup, pair<uint32_t, addr_5tup> > * map_ptr) const {
    cout << "Processing " << ref_file << endl;
    io::filtering_istream in;
    in.push(io::gzip_decompressor());
    ifstream infile(ref_file);
    in.push(infile);

    stringstream ss;
    ss << gen_trace_dir<< "/IDtrace/ptrace-";
    ss << std::setw(3) << std::setfill('0')<<id;
    ss <<".gz";
    io::filtering_ostream out_id;
    out_id.push(io::gzip_compressor());
    ofstream outfile_id (ss.str().c_str());
    out_id.push(outfile_id);
    out_id.precision(15);

    stringstream ss1;
    ss1 << gen_trace_dir<< "/GENtrace/ptrace-";
    ss1 << std::setw(3) << std::setfill('0')<<id;
    ss1 <<".gz";
    io::filtering_ostream out_loc;
    out_loc.push(io::gzip_compressor());
    ofstream outfile_gen (ss1.str().c_str());
    out_loc.push(outfile_gen);
    out_loc.precision(15);

    for (string str; getline(in, str); ) {
        addr_5tup packet (str, jesusBorn); // readable;
        if (packet.timestamp > para.simuT)
            break;
        auto iter = map_ptr->find(packet);
        if (iter != map_ptr->end()) {
            packet.copy_header(iter->second.second);
            out_id << packet.timestamp << "\t" << iter->second.first<<endl;
            out_loc << packet.str_easy_RW() << endl;
        }
    }
    cout << " Finished Processing " << ref_file << endl;
    in.pop();
    out_id.pop();
    out_loc.pop();
}

/* flow_arr_mp
 * input: string ref_trace_dir: pcap reference trace
 * 	  string flow_info_str: output trace flow first packet infol
 * output:unordered_set<addr_5tup> : the set of first packets of all flows
 *
 * function_brief:
 * obtain first packet of each flow for later flow based pruning
 */
boost::unordered_set<addr_5tup> tracer::flow_arr_mp() const {
    cout << "Processing ... To process trace files " << to_proc_files.size() << endl;
    // process using multi-thread;
    vector< std::future<boost::unordered_set<addr_5tup> > > results_exp;
    for (uint32_t file_id = 0; file_id < to_proc_files.size(); file_id++) {
        results_exp.push_back(std::async(std::launch::async, &tracer::f_arr_st, this, to_proc_files[file_id]));
    }
    vector< boost::unordered_set<addr_5tup> >results;
    for (uint32_t file_id = 0; file_id < to_proc_files.size(); file_id++) {
        boost::unordered_set<addr_5tup> res = results_exp[file_id].get();
        results.push_back(res);
    }

    // merge the results;
    boost::unordered_set<addr_5tup> flowInfo_set;
    for (uint32_t file_id = 0; file_id < to_proc_files.size(); file_id++) {
        boost::unordered_set<addr_5tup> res = results[file_id];
        for ( boost::unordered_set<addr_5tup>::iterator iter = res.begin(); iter != res.end(); iter++) {
            auto ist_res = flowInfo_set.insert(*iter);
            if (!ist_res.second) { // update timestamp;
                if (iter->timestamp < ist_res.first->timestamp) {
                    addr_5tup rec = *ist_res.first;
                    rec.timestamp = iter->timestamp;
                    flowInfo_set.insert(rec);
                }
            }
        }
    }

    // print the results;
    ofstream outfile(para.flowInfoFile_str);
    outfile.precision(15);
    for (boost::unordered_set<addr_5tup>::iterator iter = flowInfo_set.begin(); iter != flowInfo_set.end(); ++iter) {
        outfile<< iter->str_easy_RW() <<endl;
    }
    outfile.close();
    return flowInfo_set;
}

/* f_arr_st
 * input: string ref_file: trace file path
 * output:unordered_set<addr_5tup> : pairtial set of all arrival packet;
 *
 * function_brief:
 * single thread process of flow_arr_mp
 */
boost::unordered_set<addr_5tup> tracer::f_arr_st(string ref_file) const {
    cout<<"Procssing " << ref_file<< endl;
    boost::unordered_set<addr_5tup> partial_flow_rec;
    io::filtering_istream in;
    in.push(io::gzip_decompressor());
    ifstream infile(ref_file);
    in.push(infile);
    for (string str; getline(in, str); ) {
        addr_5tup packet(str, jesusBorn);
        if (packet.timestamp > para.simuT)
            break;
        partial_flow_rec.insert(packet);
    }
    io::close(in);
    cout<<"Finished procssing " << ref_file << endl;
    return partial_flow_rec;
}

/* packet_count_mp
 *
 * input: string real_trace_dir: directory of real traces
 * 	  string packet_count_file: output of packet counts
 *
 * function brief
 * counting the packets for each flow using multi-thread
 */
void tracer::packet_count_mp(string real_trace_dir, string packet_count_file) {
    fs::path dir(real_trace_dir);
    fs::directory_iterator end;
    boost::unordered_map<addr_5tup, uint32_t> packet_count_map;
    uint32_t cpu_count = count_proc();
    mutex mtx;
    atomic_uint thr_n(0);
    atomic_bool reachend(false);
    if (fs::exists(dir) && fs::is_directory(dir)) {
        fs::directory_iterator iter(dir);
        while (iter != end) {
            if ((!reachend) && fs::is_regular_file(iter->status())) { // create thread
                std::thread (&tracer::p_count_st, this, iter->path(), &thr_n, &mtx, &packet_count_map, &reachend).detach();
                thr_n++;
            }
            iter++;

            while (thr_n >= cpu_count) // block thread creation
                std::this_thread::yield();
            while (thr_n > 0 && iter == end) // give time for thread to terminate
                std::this_thread::yield();
        }
    }

    cout << "finished processing" <<endl;
    // sleep for a while for last thread to close
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // debug
    uint32_t dbtotal = 0;
    ofstream ff(packet_count_file);
    for(Map_iter iter = packet_count_map.begin(); iter != packet_count_map.end(); iter++) {
        ff<<iter->first.str_easy_RW()<<"\t"<<iter->second<<endl;
        dbtotal+=iter->second;
    }
    cout<<dbtotal<<endl;
    ff.close();
    cout << "finished copy" <<endl;
    return;
}

/* p_count_st
 *
 * input: string gz_file_ptr gz_file_ptr: file path of real traces
 * 	  atomic_unit * thr_n_ptr: control the concurrent thread no.
 * 	  mutex * mtx: control the shared access of pc_map
 * 	  unordered_map<addr_5tup, uint32_t> * pc_map_ptr: merge the results of counting
 * 	  atmoic_bool * reachend_ptr: indicate the termination of trace gen
 *
 * function brief
 * this is the thread function that produce packet counts
 */
void tracer::p_count_st(const fs::path gz_file_ptr, atomic_uint * thr_n_ptr, mutex * mtx, boost::unordered_map<addr_5tup, uint32_t> * pc_map_ptr, atomic_bool * reachend_ptr) {
    cout<<"Processing:"<<gz_file_ptr.c_str()<<endl;
    uint32_t counter = 0;
    boost::unordered_map<addr_5tup, uint32_t> packet_count_map;
    try {
        io::filtering_istream in;
        in.push(io::gzip_decompressor());
        ifstream infile(gz_file_ptr.c_str());
        in.push(infile);
        for (string str; getline(in, str); ) {
            addr_5tup packet(str, jesusBorn);
            if (packet.timestamp > para.simuT) {
                (*reachend_ptr) = true;
                break;
            }

            counter++;
            auto result = packet_count_map.insert(std::make_pair(packet, 1));
            if (!result.second)
                result.first->second = result.first->second + 1;

        }
        io::close(in);
    } catch (const io::gzip_error & e) {
        cout<<e.what()<<std::endl;
    }

    total_packet += counter;

    std::lock_guard<mutex> lock(*mtx);

    for (Map_iter iter = packet_count_map.begin(); iter != packet_count_map.end(); iter++) {
        auto result = pc_map_ptr->insert(*iter);
        if (!result.second)
            (pc_map_ptr->find(iter->first))->second += iter->second;
    }
    --(*thr_n_ptr);
}


void tracer::parse_pcap_file_mp(size_t min, size_t max) const {
    if (fs::create_directory(fs::path(para.parsed_pcap_dir)))
        cout << "creating" << para.parsed_pcap_dir <<endl;
    else
        cout << "exists: "<< para.parsed_pcap_dir<<endl;

    const size_t File_BLK = 3;
    size_t thread_no = count_proc();
    size_t block_no = (max-min + 1)/File_BLK;
    if (block_no * 3 < max-min + 1)
        ++block_no;

    if ( thread_no > block_no) {
        thread_no = block_no;
    }

    size_t task_no = block_no/thread_no;

    vector<string> to_proc;
    size_t thread_id = 1;
    vector< std::future<void> > results_exp;

    size_t counter = 0;
    fs::path dir(para.pcap_dir);
    if (fs::exists(dir) && fs::is_directory(dir)) {
        Path_Vec_T pvec;
        std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
        std::sort(pvec.begin(), pvec.end());

        for (Path_Vec_T::const_iterator it (pvec.begin()); it != pvec.end(); ++it) {
            if (counter < min) {
                ++counter;
                continue;
            }
            if (counter > max)
                break;
            ++counter;

            if (to_proc.size() < task_no*File_BLK || thread_id == thread_no) {
                to_proc.push_back(it->string());
            } else {
                cout <<"thread " << thread_id << " covers : "<<endl;
                for (auto iter = to_proc.begin(); iter != to_proc.end(); ++iter) {
                    cout << *iter << endl;
                }

                results_exp.push_back(std::async(
                                          std::launch::async,
                                          &tracer::p_pf_st,
                                          this, to_proc,
                                          (thread_id-1)*task_no)
                                     );
                ++thread_id;
                to_proc.clear();
                to_proc.push_back(it->string());
            }
        }
    }

    cout <<"thread " << thread_id << " covers :" << endl;
    for (auto iter = to_proc.begin(); iter != to_proc.end(); ++iter) {
        cout << *iter << endl;
    }

    results_exp.push_back(std::async(
                              std::launch::async,
                              &tracer::p_pf_st,
                              this, to_proc,
                              (thread_no-1)*task_no)
                         );
    for (size_t i = 0; i < thread_no; ++i)
        results_exp[i].get();

    return;
}

void tracer::p_pf_st(vector<string> to_proc, size_t id) const {
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // The actual packet

    pcap_t *handle;
    const struct sniff_ethernet * ethernet;
    const struct sniff_ip * ip;
    const struct sniff_tcp *tcp;
    uint32_t size_ip;
    uint32_t size_tcp;


    int count = 2;
    const size_t File_BLK = 3;

    stringstream ss;

    ss<<para.parsed_pcap_dir+"/packData";
    ss<<std::setw(3)<<std::setfill('0')<<id;
    ss<<"txt.gz";

    ofstream outfile(ss.str());
    cout << "created: "<<ss.str()<<endl;
    io::filtering_ostream out;
    out.push(io::gzip_compressor());
    out.push(outfile);

    for (size_t i = 0; i < to_proc.size(); ++i) {
        if (i > count) {
            out.pop();
            outfile.close();
            ss.str(string());
            ss.clear();
            ++id;
            ss<<para.parsed_pcap_dir+"/packData";
            ss<<std::setw(3)<<std::setfill('0')<<id;
            ss<<"txt.gz";
            outfile.open(ss.str());
            cout << "created: "<<ss.str()<<endl;
            out.push(outfile);
            count += File_BLK;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_offline(to_proc[i].c_str(), errbuf);

        while (true) {
            packet = pcap_next(handle, &header);
            if (packet == NULL)
                break;

            ethernet = (struct sniff_ethernet*)(packet);
            int ether_offset = 0;
            if (ntohs(ethernet->ether_type) == ETHER_TYPE_IP) {
                ether_offset = 14;
            } else if (ntohs(ethernet->ether_type) == ETHER_TYPE_8021Q) {
                // here may have a bug
                ether_offset = 18;
            } else {
                continue;
            }

            ip = (struct sniff_ip*)(packet + ether_offset);
            size_ip = IP_HL(ip)*4;

            if (IP_V(ip) != 4 || size_ip < 20)
                continue;
            if (uint32_t(ip->ip_p) != 6)
                continue;

            tcp = (struct sniff_tcp*)(packet + ether_offset + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20)
                continue;

            stringstream ss;
            ss<<header.ts.tv_sec<<'%'<<header.ts.tv_usec<<'%';
            ss<<ntohl(ip->ip_src.s_addr)<<'%'<<ntohl(ip->ip_dst.s_addr);
            ss<<'%'<<tcp->th_sport<<'%'<<tcp->th_dport;

            out<<ss.str()<<endl;
        }

        pcap_close(handle);
        cout << "finished_processing : "<< to_proc[i] << endl;
    }
    io::close(out);
}



