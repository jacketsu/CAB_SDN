#include <utility>
#include <fstream>
#include <boost/timer.hpp>
#include <boost/filesystem.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include "BucketTree.h"
using namespace std;
int bucket_tree_match(const addr_5tup & pkt,
                      const bucket_tree & bTree,
                      const rule_list & rList,
                      bucket * b
                     ) {
    bucket * matched_bucket = nullptr;

    matched_bucket = bTree.search_bucket(pkt,bTree.root);
    if(matched_bucket == nullptr) {
        return -1;
    }

    for(auto i : matched_bucket->related_rules) {
        if(rList.list[i].packet_hit(pkt)) {
            b = matched_bucket;
            return i;
        }
    }
    return -1;
}

int linear_match(const addr_5tup & pkt , const rule_list & r) {
    for(size_t i = 0; i != r.list.size(); ++i) {
        if( r.list[i].packet_hit(pkt)) {
            return i;
        }
    }
    return -1;
}

int main(int argc, char* argv[]) {

    if(argc < 3) {
        std::cerr << "Usage: TestBTree {/path/to/rule/file} {/path/to/trace/file}"
                  << std::endl;
        return 1;
    }

    //load rules
    string ruleFP(argv[1]);
    rule_list rList(ruleFP);
    boost::timer t;
    std::cerr << "loaded rules : " << rList.list.size() <<" "<<t.elapsed()<<std::endl;

    //build bucket tree
    t.restart();
    bucket_tree bTree(rList, uint32_t(15));
    std::cerr << "built bucket tree : " <<" "<<t.elapsed() << std::endl;

    //load trace and test
    ifstream traceF(argv[2]);
    if(!traceF.is_open()) {
        cerr << "can not open trace file." << endl;
        return 3;
    }

    boost::iostreams::filtering_istream traceFF;
    traceFF.push(boost::iostreams::gzip_decompressor());
    traceFF.push(traceF);

    string buf;
    while(getline(traceFF,buf)) {
        addr_5tup pkt(buf,false);
        bucket *matched_bucket = nullptr;
        int bkt_matched_id = bucket_tree_match(pkt,bTree,rList,matched_bucket);
        int lnr_matched_id = linear_match(pkt,rList);

        if(bkt_matched_id != lnr_matched_id) {
            cout << "packet " << pkt.str_readable() << endl << endl;
            if(lnr_matched_id != -1) {
                cout <<"\tlinear search match hit "<< rList.list[lnr_matched_id].get_str() << endl;
            } else {
                cout <<"\tlinear search not found."<<endl;
            }
            if(bkt_matched_id != -1) {
                cout <<"\tbucket search match hit "<< rList.list[bkt_matched_id].get_str() << endl;
                cout <<"\t\tbucket matched " << matched_bucket->get_str() <<endl;
            } else {
                cout <<"\tbucket search not found."<<endl;
            }
        }
    }
}
