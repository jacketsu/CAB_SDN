#include "RuleList.h"

using std::ifstream;
using std::ofstream;
using std::string;
using std::tie; // jiaren:missing the namespace

/* constructor
 *
 * options:
 * 	()			default
 * 	(string &)		draw from file
 */
rule_list::rule_list() {}

rule_list::rule_list(string & filename, bool test_bed) {
    ifstream file;
    file.open(filename.c_str());
    string sLine = "";
    getline(file, sLine);
    while (!file.eof()) {
        p_rule sRule(sLine, test_bed);
        list.push_back(sRule);
        getline(file, sLine);
    }
    occupancy = vector<size_t>(list.size(), 0);
    file.close();

    for(auto iter = list.begin(); iter != list.end(); ++iter) {
        for (auto iter_cp = iter+1; iter_cp != list.end(); ) {
            if (*iter == *iter_cp)
                iter_cp = list.erase(iter_cp);
            else
                ++iter_cp;
        }
    }
}

/* member func
 */
void rule_list::obtain_dep() { // obtain the dependency map
    for(uint32_t idx = 0; idx < list.size(); ++idx) {
        vector <uint32_t> dep_rules;
        for (uint32_t idx1 = 0; idx1 < idx; ++idx1) {
            if (list[idx].dep_rule(list[idx1])) {
                dep_rules.push_back(idx1);
            }
        }
        dep_map[idx] = dep_rules;
    }
}

r_rule rule_list::get_micro_rule(const addr_5tup & pack) { 
    // get the micro rule for a given packet;
    // linear search to find the matching packet
    uint32_t rule_hit_idx = 0;
    for ( ; rule_hit_idx < list.size(); ++rule_hit_idx ) {
        if (list[rule_hit_idx].packet_hit(pack))
            break;
    }

    if (rule_hit_idx == list.size()) {
        cout <<"wrong packet"<<endl;
        exit(0);
    }

    // pruning for a micro rule
    r_rule mRule = list[rule_hit_idx];
    for (auto iter = dep_map[rule_hit_idx].begin();
            iter != dep_map[rule_hit_idx].end(); ++iter) {
        mRule.prune_mic_rule(list[*iter], pack);
    }
    return mRule;
}

r_rule rule_list::get_micro_rule_split(const addr_5tup & pack){
    r_rule m_rule = get_micro_rule(pack);
    return m_rule.split_cast_TCAM(pack);
}

int rule_list::linear_search(const addr_5tup & packet) {
    for (size_t i = 0; i < list.size(); ++i) {
        if (list[i].packet_hit(packet))
            return i;
    }
    return -1;
}

void rule_list::createDAG() {
    depDag = depDAG(list.size());

    for (int i = 1; i < list.size(); ++i) {
        vector<r_rule> residual;
        residual.push_back(r_rule(list[i]));
        for (int j = i-1; i >= 0; --i) {
            if (range_minus(residual, list[i])) {
                boost::add_edge(j, i, depDag);
            }
        }
    }
}

void rule_list::obtain_cover() {
    vertex_iterator iter, end, adj_iter, adj_end;
    for (tie(iter, end) = vertices(depDag); iter != end; ++iter) {
        cover_map[*iter] = vector<uint32_t>();
        /*
        for (tie(adj_iter, adj_end) = adjacent_vertices(*iter, depDag);
                adj_iter != adj_end; ++adj_iter){
            cover_map[*iter].push_back(*adj_iter);
        }
        */
        /* jiaren */
        for (pair<adjacency_iterator, adjacency_iterator> pairAdj = adjacent_vertices(*iter, depDag);
                pairAdj.first != pairAdj.second; ++pairAdj.first) {
            cover_map[*iter].push_back(*pairAdj.first);
        }
    }
}

void rule_list::clearHitFlag() {
    for (size_t idx = 0; idx != list.size(); ++idx) {
        occupancy[idx] = 0;
        list[idx].hit = false;
    }
}


/*
 * debug and print
 */
void rule_list::print(const string & filename) {
    ofstream file;
    file.open(filename.c_str());
    for (vector<p_rule>::iterator iter = list.begin();
            iter != list.end(); iter++) {
        file<<iter->get_str()<<endl;
    }
    file.close();
}

void rule_list::rule_dep_analysis() {
    ofstream ff("rule rec");
    for (uint32_t idx = 0; idx < list.size(); ++idx) {
        ff<<"rule : "<< list[idx].get_str() << endl;
        for ( uint32_t idx1 = 0; idx1 < idx; ++idx1) {
            auto result = list[idx].join_rule(list[idx1]);
            if (result.second)
                ff << result.first.get_str()<<endl;
        }
        ff<<endl;
    }
}
