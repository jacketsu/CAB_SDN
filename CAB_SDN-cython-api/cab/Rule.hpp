#ifndef RULE_H
#define RULE_H

#include "stdafx.h"
#include <algorithm>
#include "Address.hpp"
// #include <boost/functional/hash.hpp>

class b_rule;
class r_rule;

class p_rule {
  public:
    pref_addr hostpair[2];
    range_addr portpair[2];
    bool proto;
    bool hit;
    int weight;

  public:
    inline p_rule();
    inline p_rule(const p_rule &);
    inline p_rule(const std::string &, bool = false);
    inline bool operator==(const p_rule &) const;

    inline bool dep_rule(const p_rule &) const;
    inline bool packet_hit(const addr_5tup &) const;
    inline addr_5tup get_corner() const;
    inline addr_5tup get_random() const;

    inline std::pair<p_rule, bool> join_rule(p_rule) const;
    inline b_rule cast_to_bRule() const; // May 02, 16?
    inline r_rule cast_to_rRule() const; // May 15, 17

    inline std::string get_str() const;
    inline void print() const;
};

class b_rule {
  public:
    pref_addr addrs[4];
    bool proto;

  public:
    inline b_rule();
    inline b_rule(const b_rule &);
    inline b_rule(const std::string &);

    inline bool packet_hit(const addr_5tup &) const;
    inline bool match_rule(const p_rule &) const;
    inline bool match_truncate(p_rule &) const;
    inline bool overlap(const b_rule &) const;

    inline void mutate_pred(uint32_t, uint32_t);

    inline std::string get_str() const;
    inline void print() const;

    inline void serialize_append(vector<unsigned long> & data);
};

class r_rule {
  public:
    range_addr addrs[4];
    bool proto;

  public:
    inline r_rule();
    inline r_rule(const r_rule &);
    inline r_rule(const p_rule &);

    inline bool operator==(const r_rule &) const;
    inline friend uint32_t hash_value(r_rule const &);
    inline vector<r_rule> minus(const r_rule &);  // Dec. 15  TODO to validate, 20161027 jiaren added "inline"

    inline bool overlap(const r_rule &) const;
    inline void prune_mic_rule(const r_rule &, const addr_5tup &); // Mar 14
    inline r_rule split_cast_TCAM(const addr_5tup & pack) const; // May 15
    inline friend bool range_minus(vector<r_rule> &, const r_rule &); // Dec. 15 TODO to validate

    inline p_rule cast_to_pRule() const;
    inline b_rule cast_to_bRule() const;

    inline std::string get_str() const;
};

class h_rule: public b_rule {
  private:

  public:
    std::vector<p_rule> rela_rule;

    inline h_rule(const h_rule &);
    inline h_rule(const std::string &);
    inline h_rule(const std::string &, const std::vector<p_rule> &);
    inline h_rule(const addr_5tup&, uint32_t (&)[4]);

    inline uint32_t cal_rela(const std::vector<p_rule> &);
    inline addr_5tup gen_header();
};

using std::pair;
using std::endl;

/* ----------------------------- p_rule----------------------------------
 * brief:
 * bucket_rules: two dim are prefix address, the other two are range address
 */

/* constructors
 *
 * options:
 * 	()			default
 * 	(const p_rule &)	copy function
 * 	(const string &)	generate from a string "#srcpref/mask \t dstpref/mask \t ..."
 */
inline p_rule::p_rule():hit(false) {}

inline p_rule::p_rule(const p_rule & pr) {
    hostpair[0] = pr.hostpair[0];
    hostpair[1] = pr.hostpair[1];
    portpair[0] = pr.portpair[0];
    portpair[1] = pr.portpair[1];
    proto = pr.proto;

    hit = pr.hit;
}

inline p_rule::p_rule(const string & rule_str, bool test_bed) {
    int prev = 0;
    int idx = rule_str.find_first_of("\t");
    hostpair[0] = pref_addr(rule_str.substr(1,idx-1));

    prev = idx+1;
    idx = rule_str.find_first_of("\t", prev);
    hostpair[1] = pref_addr(rule_str.substr(prev, idx-prev));

    // vector<string> temp;
    // boost::split(temp, rule_str, boost::is_any_of("\t"));
    // temp[0].erase(0,1);
    // hostpair[0] = pref_addr(temp[0]);
    // hostpair[1] = pref_addr(temp[1]);

    if (test_bed) {
        portpair[0] = range_addr();
        portpair[1] = range_addr();
    } else {
        prev = idx+1;
        idx = rule_str.find_first_of("\t", prev);
        portpair[0] = range_addr(rule_str.substr(prev, idx-prev));
        prev = idx+1;
        idx = rule_str.find_first_of("\t", prev);
        portpair[1] = range_addr(rule_str.substr(prev, idx-prev));
        // portpair[0] = range_addr(temp[2]);
        // portpair[1] = range_addr(temp[3]);
    }
    proto = true;
    hit = false;
}

inline bool p_rule::operator==(const p_rule & rhs) const {
    if (!(hostpair[0] == rhs.hostpair[0]))
        return false;
    if (!(hostpair[1] == rhs.hostpair[1]))
        return false;
    if (!(portpair[0] == rhs.portpair[0]))
        return false;
    if (!(portpair[1] == rhs.portpair[1]))
        return false;
    return true;
}

/* member fuctions
 */
inline bool p_rule::dep_rule(const p_rule & rl) const { // check whether a rule is directly dependent
    if (!hostpair[0].match(rl.hostpair[0]))
        return false;
    if (!hostpair[1].match(rl.hostpair[1]))
        return false;
    if (!portpair[0].overlap(rl.portpair[0]))
        return false;
    if (!portpair[1].overlap(rl.portpair[1]))
        return false;

    return true;
}

inline bool p_rule::packet_hit(const addr_5tup & packet) const { // check whehter a rule is hit.
    if (!hostpair[0].hit(packet.addrs[0]))
        return false;
    if (!hostpair[1].hit(packet.addrs[1]))
        return false;
    if (!portpair[0].hit(packet.addrs[2]))
        return false;
    if (!portpair[1].hit(packet.addrs[3]))
        return false;
    // ignore proto check
    return true;
}

inline pair<p_rule, bool> p_rule::join_rule(p_rule pr) const { // use this rule to join another
    if (!hostpair[0].truncate(pr.hostpair[0]))
        return std::make_pair(p_rule(), false);
    if (!hostpair[1].truncate(pr.hostpair[1]))
        return std::make_pair(p_rule(), false);
    if (!portpair[0].truncate(pr.portpair[0]))
        return std::make_pair(p_rule(), false);
    if (!portpair[1].truncate(pr.portpair[1]))
        return std::make_pair(p_rule(), false);
    return std::make_pair(pr, true);
}

inline b_rule p_rule::cast_to_bRule() const {
    b_rule br;
    br.addrs[0] = hostpair[0];
    br.addrs[1] = hostpair[1];
    br.addrs[2] = portpair[0].approx(true);
    br.addrs[3] = portpair[1].approx(true);

    return br;
}

inline addr_5tup p_rule::get_corner() const { // generate the corner as did by ClassBench
    addr_5tup header;
    header.addrs[0] = hostpair[0].get_extreme(rand()%2);
    header.addrs[1] = hostpair[1].get_extreme(rand()%2);
    header.addrs[2] = portpair[0].get_extreme(rand()%2);
    header.addrs[3] = portpair[1].get_extreme(rand()%2);
    header.proto = true;
    return header;
}

inline addr_5tup p_rule::get_random() const { // generate a random header from a rule
    addr_5tup header;
    header.addrs[0] = hostpair[0].get_random();
    header.addrs[1] = hostpair[1].get_random();
    header.addrs[2] = portpair[0].get_random();
    header.addrs[3] = portpair[1].get_random();
    header.proto = true;
    return header;
}

/* debug & print function
 */
inline void p_rule::print() const {
    cout<<get_str()<<endl;
}

inline string p_rule::get_str() const {
    stringstream ss;
    ss<<hostpair[0].get_str()<<"\t";
    ss<<hostpair[1].get_str()<<"\t";
    ss<<portpair[0].get_str()<<"\t";
    ss<<portpair[1].get_str()<<"\t";
    if (proto)
        ss<<"tcp";
    else
        ss<<"udp";
    return ss.str();
}

/* ----------------------------- b_rule----------------------------------
 * brief:
 * bucket_rules: four dimensions are all prefix address
 */


/* constructors
 * option:
 * 	()			default
 * 	(const b_rule &)	copy
 * 	(const string &)	generate from a string "srcpref/mask \t dstpref/mask \t ..."
 */
inline b_rule::b_rule() { // constructor default
    addrs[2].mask = ((~(unsigned)0)<<16); // port is limited to 0~65535
    addrs[3].mask = ((~(unsigned)0)<<16);
}

inline b_rule::b_rule(const b_rule & br) { // copy constructor
    for(uint32_t i=0; i<4; i++) {
        addrs[i] = br.addrs[i];
    }
    proto = br.proto;
}

inline b_rule::b_rule(const string & rule_str) { // construct from string
    // vector<string> temp;
    // boost::split(temp, rule_str, boost::is_any_of("\t"));
    // for(uint32_t i=0; i<4; i++) {
    //     addrs[i] = pref_addr(temp[i]);
    // }
    
    int idx = -1;
    int prev = 0;
    for(int i = 0; i < 4; ++i){
        prev = idx+1;
        idx = rule_str.find_first_of("\t", prev);
        addrs[i] = rule_str.substr(prev, idx-prev); 
    }
}

/* member funcs
 */
inline bool b_rule::packet_hit(const addr_5tup & packet) const { // check packet hit a bucket
    for (uint32_t i = 0; i < 4; i++) {
        if (!addrs[i].hit(packet.addrs[i]))
            return false;
    }
    // ignore proto check
    return true;
}

inline bool b_rule::match_rule(const p_rule & rule) const { // check whether a policy rule is in bucket
    if (!rule.hostpair[0].match(addrs[0]))
        return false;
    if (!rule.hostpair[1].match(addrs[1]))
        return false;
    if (!rule.portpair[0].match(addrs[2]))
        return false;
    if (!rule.portpair[1].match(addrs[3]))
        return false;
    return true;
}

inline bool b_rule::match_truncate(p_rule & rule) const { // truncate a policy rule using a bucket
    if (!addrs[0].truncate(rule.hostpair[0]))
        return false;
    if (!addrs[1].truncate(rule.hostpair[1]))
        return false;
    if (!addrs[2].truncate(rule.portpair[0]))
        return false;
    if (!addrs[3].truncate(rule.portpair[1]))
        return false;
    return true;
}

inline bool b_rule::overlap(const b_rule & br) const {
    for (uint32_t i = 0; i < 4; ++i) {
        if (!addrs[i].match(br.addrs[i]))
            return false;
    }
    return true;
}

inline void b_rule::mutate_pred(uint32_t shrink_scale, uint32_t expand_scale) {
    for (uint32_t i = 0; i < 2; ++i)
        addrs[i].mutate(shrink_scale, expand_scale, false);
    for (uint32_t i = 2; i < 4; ++i) {
        addrs[i].mutate(shrink_scale/2, expand_scale/2, true);
    }
}

/* debug & print function
 */
inline void b_rule::print() const { // print func
    cout<<get_str()<<endl;
}

inline string b_rule::get_str() const { // print func
    stringstream ss;
    for(uint32_t i = 0; i < 4; i++) {
        ss<<addrs[i].get_str()<<"\t";
    }
    return ss.str();
}


/* ----------------------------- r_rule----------------------------------
 * brief:
 * range_rules: four dimensions are all range_addr
 */

/* constructors
 *
 * options:
 * 	()			default
 * 	(const r_rule &)	copy
 * 	(const p_rule &)	tranform out of a p_rule
 */
inline r_rule::r_rule() {
    addrs[0] = range_addr(0, ~uint32_t(0));
    addrs[1] = range_addr(0, ~uint32_t(0));
    addrs[2] = range_addr(0, (~uint32_t(0) >> 16));
    addrs[3] = range_addr(0, (~uint32_t(0) >> 16));
}

inline r_rule::r_rule(const r_rule & pr) {
    for (uint32_t i = 0; i < 4; ++i)
        addrs[i] = pr.addrs[i];
}

inline r_rule::r_rule(const p_rule & pr) {
    addrs[0] = range_addr(pr.hostpair[0]);
    addrs[1] = range_addr(pr.hostpair[1]);
    addrs[2] = pr.portpair[0];
    addrs[3] = pr.portpair[1];
    proto = pr.proto;
}

/* operator functions
 *
 * for hash based containers
 */

inline bool r_rule::operator==(const r_rule & rhs) const {
    for (uint32_t i = 0; i < 4; i++)
        if (!(addrs[i] == rhs.addrs[i]))
            return false;
    return true;
}

inline uint32_t hash_value(r_rule const & rr) { // hash the detailed range value for the value;
    size_t seed = 0;
    hash<uint32_t> hasher;
    for (uint32_t i = 0; i < 4; ++i) {
        seed ^= hasher(hash_value(rr.addrs[i])) + (seed<<6) + (seed>>2);
        //boost::hash_combine(seed, hash_value(rr.addrs[i]));
    }
    return seed;
}

//jiaren inline
inline vector<r_rule> r_rule::minus(const r_rule & mRule){
    vector<r_rule> result;

    vector<vector<range_addr> > field_div;
    
    for (int i = 0; i < 4; ++i){
        field_div.push_back(minus_range(addrs[i], mRule.addrs[i]));
    }

    for (int i = 0; i < 4; ++i){
        for (range_addr radd : field_div[i]){
            r_rule res = mRule;
            res.addrs[i] = radd;
            for (int j = i+1; j < 4; ++j){
                res.addrs[j] = addrs[j];
            }
            result.push_back(res);
        }
    }
    return result;
}

/* member functions
 */
inline bool r_rule::overlap (const r_rule & rr) const { // check whether another r_rule overlap with it.
    for (uint32_t i = 0; i < 4; ++i) {
        if (!addrs[i].overlap(rr.addrs[i]))
            return false;
    }
    return true;
}


inline void r_rule::prune_mic_rule(const r_rule & rr, const addr_5tup & pack) { // use another r_rule, and pack to prune to a r_rule that tightest to the packet hit.
    for (uint32_t i = 0; i< 4; ++i) {
        addrs[i].getTighter(pack.addrs[i], rr.addrs[i]);
    }
}

inline r_rule r_rule::split_cast_TCAM(const addr_5tup & pack) const {
    p_rule pr;
    pr.hostpair[0] = addrs[0].split_to_hit(pack.addrs[0]);
    pr.hostpair[1] = addrs[1].split_to_hit(pack.addrs[1]); 
    pr.portpair[2] = addrs[2];
    pr.portpair[3] = addrs[3];

    return pr;
} 

inline b_rule r_rule::cast_to_bRule() const {
    b_rule br;
    br.addrs[0] = addrs[0].approx(false);
    br.addrs[1] = addrs[1].approx(false);
    br.addrs[2] = addrs[2].approx(true);
    br.addrs[3] = addrs[3].approx(true);

    return br;
}

inline void b_rule::serialize_append(vector<unsigned long> & data){
    data.push_back(addrs[0].pref);
    data.push_back(addrs[0].mask);
    data.push_back(addrs[1].pref);
    data.push_back(addrs[1].mask);
    data.push_back(addrs[2].pref);
    data.push_back(addrs[2].mask);
    data.push_back(addrs[3].pref);
    data.push_back(addrs[3].mask);
}

inline bool range_minus(vector<r_rule> & toMinusRules, const r_rule & mRule){
    bool overlap = false;
    for (auto iter = toMinusRules.begin(); iter != toMinusRules.end(); ){
        if (iter->overlap(mRule)){
            auto result = iter->minus(mRule);
            iter = toMinusRules.erase(iter);
            for (auto & mR : result)
                iter = toMinusRules.insert(iter, mR);
            iter += result.size();
            overlap = true;
        }
        else{
            ++iter;
        }
    }
    return overlap;
}

/* print and debug
 */
inline string r_rule::get_str() const {
    stringstream ss;
    for(uint32_t i = 0; i < 4; i++) {
        ss<<addrs[i].get_str()<<"\t";
    }
    return ss.str();
}

/* ----------------------------- h_rule----------------------------------
 * brief:
 * hot_rules: four dimensions are all prefix rule
 */

inline h_rule::h_rule(const string & line):b_rule(line) {};

inline h_rule::h_rule(const h_rule & hr):b_rule(hr) {
    rela_rule = hr.rela_rule;
}

inline h_rule::h_rule(const string & str, const vector<p_rule> & rL):b_rule(str) {
    cal_rela(rL);
}

inline h_rule::h_rule(const addr_5tup & center, uint32_t (& scope)[4]) {
    for (uint32_t i = 0; i < 2; i++) {
        if (scope[i] < 32) {
            addrs[i].pref = (center.addrs[i] & ((~0)<<scope[i]));
            addrs[i].mask = ((~0)<<scope[i]);
        } else {
            addrs[i].pref = 0;
            addrs[i].mask = 0;
        }
    }
    for (uint32_t i = 2; i < 4; i++) {
        if (scope[i] < 16) {
            addrs[i].pref = (center.addrs[i] & ((~0)<<scope[i]));
            addrs[i].mask = ((~unsigned(0))<<scope[i]);
        } else {
            addrs[i].pref = 0;
            addrs[i].mask = ((~unsigned(0))<<16);
        }
    }
}

inline uint32_t h_rule::cal_rela(const vector<p_rule> & rList) {
    for (uint32_t i = 0; i < rList.size(); i++) {
        p_rule rule = rList[i]; // copy
        if(match_truncate(rule)) {
            rela_rule.push_back(rule);
        }
    }
    return rela_rule.size();
}

inline addr_5tup h_rule::gen_header() {
    vector<p_rule>::iterator iter = rela_rule.begin();
    advance(iter, rand()%rela_rule.size());
    return iter->get_random();
}

#endif




