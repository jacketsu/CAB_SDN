#include "CABcython.h"
#include "Rule.hpp"
#include "RuleList.h"
#include "BucketTree.h"
#include <iostream> 

using std::cout;
using std::endl;
// static bucket_tree * bTree = NULL;
bucket_tree * bTree = NULL;
rule_list * rList = NULL;
// static rule_list * rList = NULL;

CABcython::CABcython() {}

CABcython::CABcython(string rule_file, int thres_hard){
    rList = new rule_list(rule_file);
    size_t pre_alloc_no = 0;
    bTree = new bucket_tree(*rList, thres_hard, false, pre_alloc_no);
    cout << "Done creating bucket Tree" << endl;
}

vector<unsigned long> CABcython::queryBTree(vector<unsigned long> pktQuery){
    addr_5tup pkt(pktQuery);
    vector<unsigned long> data;

    bucket * bkt = bTree->search_bucket(pkt, bTree->root).first;
    bkt->serialize_append(data);

    // cast to B Rule to avoid range rules
    // note: pls generate synthetic traffic using casted pRules
    //       instead of directly using pRule, otherwise it could 
    //       constantly mis-match.
    
    for (int id : bkt->related_rules){
        // cout << id << " "; 
        rList->list[id].cast_to_bRule().serialize_append(data);
    }
    // cout << endl;

    return data;
}

CABcython::~CABcython(){
    delete bTree;
    delete rList;
}
