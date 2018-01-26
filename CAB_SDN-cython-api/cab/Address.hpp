#ifndef ADDRESS_H
#define ADDRESS_H

#include "stdafx.h"
#include <functional>
#include <algorithm>
// #include <boost/functional/hash.hpp>
using std::vector;
using std::hash;

class range_addr;

class EpochT {
    long int sec;
    long int msec;

public:
    inline EpochT():sec(0),msec(0) {}

    inline EpochT(int isec, int imsec):sec(isec),msec(imsec) {}

    inline EpochT(const std::string & str) {
        int idx = str.find_first_of("%");
        sec = stoi(str.substr(0, idx));
        msec = stoi(str.substr(idx+1));
        // std::vector<std::string> temp;
        // boost::split(temp, str, boost::is_any_of("%"));
        // sec = boost::lexical_cast<uint32_t> (temp[0]);
        // msec = boost::lexical_cast<uint32_t> (temp[1]);
    }

    inline EpochT(const double & dtime) {
        sec = int(dtime);
        msec = int((dtime-sec)*1000000);
    }

    inline EpochT(const int & itime) {
        sec = int(itime);
        msec = 0;
    }

    inline EpochT(const EpochT & rhs) {
        sec = rhs.sec;
        msec = rhs.msec;
    }

    /*
    inline EpochT& operator=(const EpochT & rhs){
    	sec = rhs.sec;
    	msec = rhs.msec;
    	return *this;
    }*/

    inline EpochT operator+(const double & dtime) const {
        long sec = this->sec + int(dtime);
        long msec = this->msec + int((dtime-int(dtime))*1000000);
        if (msec > 1000000) {
            msec -= 1000000;
            sec += 1;
        }
        EpochT res(sec, msec);
        return res;
    }

    inline EpochT operator+(const int & rhs) const {
        EpochT res(this->sec+rhs, this->msec);
        return res;
    }

    inline EpochT operator+(const EpochT & rhs) const {
        long sec = this->sec+rhs.sec;
        long msec = this->msec+rhs.sec;
        if (msec > 1000000) {
            msec -= 1000000;
            sec += 1;
        }
        EpochT res(sec, msec);
        return res;
    }

    inline EpochT operator-(const EpochT & rhs) const {
        long sec = this->sec-rhs.sec;
        long msec = this->msec-rhs.sec;
        if (msec < 0) {
            msec += 1000000;
            sec -= 1;
        }
        EpochT res(sec, msec);
        return res;
    }

    bool operator<(const EpochT & rhs) const {
        if (this->sec < rhs.sec) {
            return true;
        } else if(this->sec == rhs.sec) {
            if (this->msec < rhs.sec)
                return true;
        }
        return false;
    }

    double toDouble(const EpochT & offset) const {
        double res = this->sec - offset.sec;
        res += double(this->msec - offset.msec)/1000000;
        return res;
    }

};

class addr_5tup {
public:
    uint32_t addrs[4];
    bool proto;
    double timestamp;

public:
    inline addr_5tup();
    inline addr_5tup(const addr_5tup &);
    inline addr_5tup(const vector<unsigned long> &); // for cython
    inline addr_5tup(const std::string &); // processing gen
    inline addr_5tup(const std::string &, const EpochT &); // processing raw
    inline addr_5tup(const std::string &, double);

    inline void copy_header(const addr_5tup &);
    inline bool operator==(const addr_5tup &) const;
    inline friend uint32_t hash_value(addr_5tup const &);

    inline std::string str_readable() const;
    inline std::string str_easy_RW() const;
};


class pref_addr {
public:
    uint32_t pref;
    uint32_t mask;

public:
    inline pref_addr();
    inline pref_addr(const pref_addr &);
    inline pref_addr(const std::string &);

    inline bool operator==(const pref_addr &) const;

    inline bool match (const pref_addr &) const;
    inline bool hit (const uint32_t &) const;
    inline uint32_t get_extreme(bool) const;
    inline uint32_t get_random() const;
    inline bool truncate(pref_addr &) const;
    inline bool truncate(range_addr &) const;

    inline void mutate(uint32_t, uint32_t, bool);

    inline void print() const;
    inline std::string get_str() const;
};


class range_addr {
public:
    uint32_t range[2];

public:
    inline range_addr();
    inline range_addr(const range_addr &);
    inline range_addr(const std::string &);
    inline range_addr(const pref_addr & );
    inline range_addr(uint32_t, uint32_t);

    inline bool operator<(const range_addr &) const;
    inline bool operator==(const range_addr &) const;
    inline friend uint32_t hash_value(range_addr const & ra);

    inline bool overlap (const range_addr &) const;
    inline range_addr intersect(const range_addr &) const;
    inline pref_addr split_to_hit (const uint32_t &) const;
    inline bool truncate(range_addr &) const;
    inline bool match (const pref_addr &) const;
    inline bool hit (const uint32_t &) const;
    inline void getTighter(const uint32_t &, const range_addr &);  // Mar 14
    inline pref_addr approx(bool is_port) const; // May 02
    inline friend std::vector<range_addr> minus_range(const range_addr &, const range_addr &); // Dec 14
    inline friend std::vector<range_addr> minus_rav(std::vector<range_addr> &, std::vector<range_addr> &);

    inline uint32_t get_extreme(bool) const;
    inline uint32_t get_random() const;

    inline void print() const;
    inline std::string get_str() const;
};


// ---------------------- Addr_5tup ---------------------
using std::vector;
using std::string;
using std::stringstream;
using std::cout;
using std::endl;

inline addr_5tup::addr_5tup() {
    for (uint32_t i = 0; i < 4; i++)
        addrs[i] = 0;
    proto = true;
    timestamp = 0;
}

inline addr_5tup::addr_5tup(const addr_5tup & ad) {
    for (uint32_t i = 0; i < 4; i++)
        addrs[i] = ad.addrs[i];
    proto = ad.proto;
    timestamp = ad.timestamp;
}

inline addr_5tup::addr_5tup(const vector<unsigned long> & pktArray){
    for (int i = 0; i < 4; ++i){
        addrs[i] = pktArray[i];
    }
    proto = true;
    timestamp = 0;
}

inline addr_5tup::addr_5tup(const string & str) {
    // vector<string> temp;
    // boost::split(temp, str, boost::is_any_of("%"));
    // timestamp = boost::lexical_cast<double>(temp[0]);
    // addrs[0] = boost::lexical_cast<uint32_t>(temp[1]);
    // addrs[1] = boost::lexical_cast<uint32_t>(temp[2]);
    // addrs[2] = boost::lexical_cast<uint32_t>(temp[3]);
    // addrs[3] = boost::lexical_cast<uint32_t>(temp[4]);
    //
    proto = true;

    int prev = 0;
    int idx = str.find_first_of("%");
    timestamp = stod(str.substr(prev, idx));
    
    for (int i = 0; i < 4; ++i){
        prev = idx+1;
        idx = str.find_first_of("%", prev);
        addrs[0] = stoul(str.substr(prev, idx - prev));
    }
}

inline addr_5tup::addr_5tup(const string & str, const EpochT & offset) {
    // vector<string> temp;
    // boost::split(temp, str, boost::is_any_of("%"));
    // proto = true;
    // EpochT ts_ep(boost::lexical_cast<uint32_t>(temp[0]), boost::lexical_cast<uint32_t>(temp[1]));
    // timestamp = ts_ep.toDouble(offset);
    // addrs[0] = boost::lexical_cast<uint32_t>(temp[2]);
    // addrs[1] = boost::lexical_cast<uint32_t>(temp[3]);
    // addrs[2] = boost::lexical_cast<uint32_t>(temp[4]);
    // addrs[3] = boost::lexical_cast<uint32_t>(temp[5]);
    proto = true;
    int prev = 0;
    int idx = str.find_first_of("%");
    int sec = stoul(str.substr(prev, idx));
    prev = idx+1;
    int msec = stoul(str.substr(prev, idx - prev));
    EpochT ts_ep(sec, msec);
    timestamp = ts_ep.toDouble(offset);

    for (int i = 0; i < 4; ++i){
        prev = idx+1;
        idx = str.find_first_of("%", prev);
        addrs[0] = stoul(str.substr(prev, idx - prev));
    }
}

/*
inline addr_5tup::addr_5tup(const string & str, bool readable) {
    vector<string> temp;
    boost::split(temp, str, boost::is_any_of("%"));
    // ts
    timestamp = boost::lexical_cast<double>(temp[0]);
    proto = true;
    // ip
    if (readable) {
        vector<string> temp1;
        boost::split(temp1, temp[1], boost::is_any_of("."));
        addrs[0] = 0;
        for(uint32_t i=0; i<4; i++) {
            addrs[0] = (addrs[0]<<8) + boost::lexical_cast<uint32_t>(temp1[i]);
        }
        boost::split(temp1, temp[2], boost::is_any_of("."));
        addrs[1] = 0;
        for(uint32_t i=0; i<4; i++) {
            addrs[1] = (addrs[1]<<8) + boost::lexical_cast<uint32_t>(temp1[i]);
        }
    } else {
        addrs[0] = boost::lexical_cast<uint32_t>(temp[1]);
        addrs[1] = boost::lexical_cast<uint32_t>(temp[2]);
    }
    // port
    addrs[2] = boost::lexical_cast<uint32_t>(temp[3]);
    addrs[3] = boost::lexical_cast<uint32_t>(temp[4]);
    // proto neglect
}
*/


inline addr_5tup::addr_5tup(const string & str, double ts) {
    // vector<string> temp;
    // boost::split(temp, str, boost::is_any_of("\t"));
    // timestamp = ts;
    // proto = true;
    // for (uint32_t i = 0; i < 4; i++) {
    //     addrs[i] = boost::lexical_cast<uint32_t>(temp[i]);
    // }

    proto = 0;
    timestamp = ts;

    int prev = 0;
    int idx = -1;

    for (int i = 0; i < 4; ++i){
        prev = idx+1;
        idx = str.find_first_of("%");
        addrs[i] = stoul(str.substr(prev, idx-prev)); 
    }
}

inline void addr_5tup::copy_header(const addr_5tup & ad) {
    for (uint32_t i = 0; i < 4; i++)
        addrs[i] = ad.addrs[i];
    proto = ad.proto;
}

inline bool addr_5tup::operator==(const addr_5tup & rhs) const {
    for (uint32_t i = 0; i < 4; i++) {
        if (addrs[i] != rhs.addrs[i])
            return false;
    }
    return (proto == rhs.proto);
}

inline uint32_t hash_value(addr_5tup const & packet) {
    size_t seed = 0;
    // boost::hash_combine(seed, packet.addrs[0]);
    // boost::hash_combine(seed, packet.addrs[1]);
    // boost::hash_combine(seed, packet.addrs[2]);
    // boost::hash_combine(seed, packet.addrs[3]);
    
    hash<uint32_t> hasher;
    seed ^= hasher(packet.addrs[0]) + (seed<<6) + (seed>>2);
    seed ^= hasher(packet.addrs[1]) + (seed<<6) + (seed>>2);
    seed ^= hasher(packet.addrs[2]) + (seed<<6) + (seed>>2);
    seed ^= hasher(packet.addrs[3]) + (seed<<6) + (seed>>2);
    return seed;
}

inline string addr_5tup::str_readable() const {
    stringstream ss;
    ss.precision(15);
    ss<<timestamp<<"%";
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0; j < 4; j++) {
            ss << ((addrs[i] >> (24-8*j)) & ((1<<8)-1));
            if (j!=3)
                ss<<".";
        }
        ss<<"%";
    }
    for (uint32_t i = 2; i < 4; i++)
        ss<<addrs[i]<<"%";

    if (proto)
        ss<<"6";
    else
        ss<<"13";
    return ss.str();
}

inline string addr_5tup::str_easy_RW() const {
    stringstream ss;
    ss.precision(15);
    ss<<timestamp<<"%";
    for (uint32_t i = 0; i < 4; i++) {
        ss<<addrs[i]<<"%";
    }
    if (proto)
        ss<<"1";
    else
        ss<<"0";
    return ss.str();
}



/* Constructor with string input
 * parse the string in form of
 * 127.0.0.1 \t 10.0.0.1 \t 1023 \t 24 \t tcp
 * to 5tup
*/
/*
addr_5tup::addr_5tup(string addr_str){

}*/



// ---------------------- pref_addr ---------------------

inline pref_addr::pref_addr() {
    pref = 0;
    mask = 0;
}

inline pref_addr::pref_addr(const string & prefstr) {
    // vector<string> temp1;
    // boost::split(temp1, prefstr, boost::is_any_of("/"));

    // uint32_t maskInt = boost::lexical_cast<uint32_t>(temp1[1]);
    int idx = prefstr.find_first_of("/");
    uint32_t maskInt = stoul(prefstr.substr(idx+1));
    mask = 0;
    pref = 0;

    string pStr = prefstr.substr(0, idx);
    idx = -1;
    int prev = 0;

    for (int i = 0; i < 4; ++i){
        prev = idx+1;
        idx = pStr.find_first_of(".", prev);
        pref = (pref<<8) + stoul(prefstr.substr(prev, idx-prev));
    }
    
    pref=(pref & mask);

    // if (maskInt != 0)
    //     mask = ((~uint32_t(0)) << (32-maskInt));

    // vector<string> temp2;
    // boost::split(temp2, temp1[0], boost::is_any_of("."));

    // pref = 0;
    // for(uint32_t i=0; i<4; i++) {
    //     pref = (pref<<8) + boost::lexical_cast<uint32_t>(temp2[i]);
    // }
}

inline pref_addr::pref_addr(const pref_addr & pa) {
    pref = pa.pref;
    mask = pa.mask;
}

inline bool pref_addr::operator==(const pref_addr & rhs) const {
    if (pref != rhs.pref)
        return false;
    if (mask != rhs.mask)
        return false;
    return true;
}

inline bool pref_addr::hit(const uint32_t & ad) const {
    return (pref == (ad & mask));
}

inline bool pref_addr::match(const pref_addr & ad) const {
    uint32_t mask_short;
    if (mask > ad.mask)
        mask_short = ad.mask;
    else
        mask_short = mask;

    return ((pref & mask_short) == (ad.pref & mask_short));
}

inline uint32_t pref_addr::get_extreme(bool hi) const {
    if (hi)
        return (pref+(~mask));
    else
        return pref;
}

inline uint32_t pref_addr::get_random() const {
    if (!(~mask+1))
        return pref;
    return (pref + rand()%(~mask+1));
}

inline bool pref_addr::truncate(pref_addr & rule) const {
    if (rule.mask < mask) { // trunc
        if (rule.pref == (pref & rule.mask)) {
            rule.mask = mask;
            rule.pref = pref;
            return true;
        } else
            return false;
    } else {
        if ((rule.pref & mask) == pref)
            return true;
        else
            return false;
    }
}

inline bool pref_addr::truncate(range_addr & rule) const {
    if (rule.range[1] < pref || rule.range[0] > pref+(~mask))
        return false;

    if (rule.range[0] < pref)
        rule.range[0] = pref;
    if (rule.range[1] > pref+(~mask))
        rule.range[1] = pref+(~mask);

    return true;
}

inline void pref_addr::mutate(uint32_t s_shrink, uint32_t s_expand, bool port) {
    if (rand()%2 > 0) { // expand
        if (s_expand == 0)
            s_expand = 1;
        uint32_t mdig = rand() % (s_expand+1);
        for (uint32_t i = 0; i < mdig; ++i) {
            if ((mask == 0 && !port) || (mask == ((~unsigned(0)) << 16) && port))
                break;
            mask = mask << mdig;
        }
        pref = pref & mask;
    } else { // shrink
        if (s_shrink == 0)
            s_shrink = 1;
        uint32_t mdig = rand() % (s_shrink+1);
        for (uint32_t i = 0; i < mdig; ++i) {
            if (~mask == 0)
                break;
            uint32_t new_mask = (mask >> 1) + (1 << 31);
            pref += (rand()%2 * (new_mask - mask));
            mask = new_mask;
        }
        pref = pref & mask;
    }
}

inline void pref_addr::print() const {
    cout<<get_str()<<endl;
}

inline string pref_addr::get_str() const {
    stringstream ss;
    for (uint32_t i = 0; i<4; i++) {
        ss<<((pref>>(24-(i*8))&((1<<8)-1)));
        if (i != 3)
            ss<<".";
    }
    ss<<"/";

    uint32_t m = 0;
    uint32_t mask_cp = mask;

    if ((~mask_cp) == 0) {
        ss<<32;
        return ss.str();
    }
    for (uint32_t i=0; mask_cp; i++) {
        m++;
        mask_cp = (mask_cp << 1);
    }
    ss<<m;
    return ss.str();
}


/* ---------------------- range_addr ---------------------
 * brief:
 * range address: two icons are range start and termin
 */

/* constructors:
 *
 * options:
 * 	()			default
 * 	(const range_addr &)	copy
 * 	(const string &)	generate from a string  "1:1024"
 * 	(const pref_addr &)	transform out of a prefix_addr
 * 	(uint32_t, uint32_t)	explicitly initialize with range value
 */
inline range_addr::range_addr() {
    range[0] = 0;
    range[1] = 0;
}

inline range_addr::range_addr(const range_addr & ra) {
    range[0] = ra.range[0];
    range[1] = ra.range[1];
}

inline range_addr::range_addr(const string & rangestr) {
    vector<string> temp1;
    // boost::split(temp1, rangestr, boost::is_any_of(":"));
    // boost::trim(temp1[0]);
    // boost::trim(temp1[1]);
    int idx = rangestr.find_first_of(":");
    range[0] = stoul(rangestr.substr(0,idx));
    range[1] = stoul(rangestr.substr(idx+1));

    // range[0] = boost::lexical_cast<uint32_t> (temp1[0]);
    // range[1] = boost::lexical_cast<uint32_t> (temp1[1]);
}

inline range_addr::range_addr(const pref_addr & rule) {
    range[0] = rule.pref;
    range[1] = rule.pref + (~rule.mask);
}

inline range_addr::range_addr(uint32_t i, uint32_t j) {
    range[0] = i;
    range[1] = j;
}

/* operator functions
 *
 * for hash_bashed and comparison based use
 */
inline bool range_addr::operator<(const range_addr & ra) const {
    return range[0]< ra.range[0];
}

inline bool range_addr::operator==(const range_addr & ra) const {
    return ( range[0] == ra.range[0] && range[1] == ra.range[1]);
}

inline uint32_t hash_value(range_addr const & ra) {
    size_t seed = 0;
    hash<uint32_t> hasher;
    seed ^= hasher(ra.range[0]) + (seed<<6) + (seed>>2);
    seed ^= hasher(ra.range[1]) + (seed<<6) + (seed>>2);
    // boost::hash_combine(seed, ra.range[0]);
    // boost::hash_combine(seed, ra.range[1]);
    return seed;
}

/* member function
 */
inline bool range_addr::overlap(const range_addr & ad) const { // whether two range_addr overlap  sym
    return (!(range[1] < ad.range[0]) || (range[0] > ad.range[1]));
}

inline range_addr range_addr::intersect(const range_addr & ra) const { // return the join of two range addr  sym
    uint32_t lhs = range[0] > ra.range[0] ? range[0] : ra.range[0];
    uint32_t rhs = range[1] < ra.range[1] ? range[1] : ra.range[1];
    return range_addr(lhs, rhs);
}

inline pref_addr range_addr::split_to_hit(const uint32_t & pkt_val) const {
    int maskInt;

    for (maskInt = 32; maskInt > 0; --maskInt){
        uint32_t mask = ((~uint32_t(0)) << (32-maskInt));
        
        uint32_t lower = pkt_val & mask;
        uint32_t higher = lower + (~mask);
        
        if (lower < range[0] || higher > range[1]){
            break;    
        }   
    }

    if (maskInt == 0){
        if (0 < range[0] || ~0 > range[1]){
            maskInt = 1;
        }
        else{
            maskInt = 0;
        }
    }
    else{
        maskInt++; 
    }

    uint32_t mask = ((~uint32_t(0)) << (32-maskInt));
    pref_addr pa;
    pa.pref = pkt_val & mask;
    pa.mask = mask; 

    return pa;
}

inline bool range_addr::truncate(range_addr & ra) const { // truncate a rule using current rule  sym
    if (ra.range[0] > range[1] || ra.range[1] < range[0])
        return false;
    if (ra.range[0] < range[0])
        ra.range[0] = range[0];
    if (ra.range[1] > range[1])
        ra.range[1] = range[1];
    return true;
}

inline bool range_addr::match(const pref_addr & ad) const { // whether a range matchs a prefix  sym
    return (! ((range[1] & ad.mask) < ad.pref || (range[0] & ad.mask) > ad.pref));
}

inline bool range_addr::hit(const uint32_t & ad) const { // whether a packet hit
    return (range[0] <= ad && range[1] >= ad);
}

inline void range_addr::getTighter(const uint32_t & hit, const range_addr & ra) { // get the micro address
    if (ra.range[0] <= hit && ra.range[0] > range[0]) {
        range[0] = ra.range[0];
    }

    if (ra.range[1] < hit && ra.range[1] > range[0]) {
        range[0] = ra.range[1]+1;
    }

    if (ra.range[0] > hit && ra.range[0] < range[1]) {
        range[1] = ra.range[0] - 1;
    }

    if (ra.range[1] >= hit && ra.range[1] < range[1]) {
        range[1] = ra.range[1];
    }
}

inline pref_addr range_addr::approx(bool is_port = true) const {
    if ((range[1] == ~0) && (range[0] == 0)) {
        pref_addr p_addr ("0.0.0.0/0");
        return p_addr;
    }
    int length = range[1] - range[0] + 1;
    int app_len = 1;

    while (length/2 > 0) {
        app_len = app_len * 2;
        length = length/2;
    }

    pref_addr p_addr;
    int mid = range[1] - range[1] % app_len;
    if ( mid + app_len - 1 <= range[1] ) {
        p_addr.pref = mid;
    } else {
        if (mid - app_len >= range[0])
            p_addr.pref = mid - app_len;
        else {
            app_len = app_len/2;
            if (mid + app_len - 1 <= range[1])
                p_addr.pref = mid;
            else
                p_addr.pref = mid - app_len/2;
        }
    }

    p_addr.mask = ~0;
    while (app_len > 1) {
        p_addr.mask = p_addr.mask << 1;
        app_len = app_len/2;
    }

    if (is_port) // port only has the last 16 bits.
        p_addr.mask = p_addr.mask | ((~unsigned(0))<<16);
    p_addr.pref = p_addr.pref & p_addr.mask;
    return p_addr;
}

inline vector<range_addr> minus_rav(vector<range_addr> & lhs, vector<range_addr> & rhs) { // minus the upper rules
    vector <range_addr> res;
    std::sort(lhs.begin(), lhs.end());
    std::sort(rhs.begin(), rhs.end());
    vector<range_addr>::const_iterator iter_l = lhs.begin();
    vector<range_addr>::const_iterator iter_r = rhs.begin();
    while (iter_l != lhs.end()) {
        uint32_t lb = iter_l->range[0];
        while (iter_r != rhs.end()) {
            if (iter_r->range[1] < iter_l->range[0]) {
                iter_r++;
                continue;
            }
            if (iter_r->range[0] > iter_l->range[1]) {
                break;
            }
            range_addr minus_item = iter_l->intersect(*iter_r);
            if (lb < minus_item.range[0])
                res.insert(res.end(), range_addr(lb, minus_item.range[0]-1));
            lb = minus_item.range[1]+1;
            iter_r++;
        }
        if (lb <= iter_l->range[1])
            res.insert(res.end(), range_addr(lb, iter_l->range[1]));
        iter_l++;
    }
    return res;
}

inline vector<range_addr> minus_range(const range_addr & lhs, const range_addr & rhs) {
    if (rhs.range[0] <= lhs.range[0]) {
        if (rhs.range[1] < lhs.range[0])
            return vector<range_addr>(1,lhs);
        if (rhs.range[1] < lhs.range[1])
            return vector<range_addr>(1, range_addr(rhs.range[1]+1, lhs.range[1]));
        return vector<range_addr>();
    }
    if (rhs.range[0] <= lhs.range[1]) {
        if (rhs.range[1] >= lhs.range[1])
            return vector<range_addr>(1, range_addr(lhs.range[0], rhs.range[0] - 1));

        vector<range_addr> result;
        result.push_back(range_addr(lhs.range[0], rhs.range[0]-1));
        result.push_back(range_addr(rhs.range[1]+1, lhs.range[1]));
        return result;
    }
    return vector<range_addr>(1,lhs);
}

inline uint32_t range_addr::get_extreme(bool hi) const { // get the higher or lower range of the addr
    if (hi)
        return range[1];
    else
        return range[0];
}

inline uint32_t range_addr::get_random() const { // get a random point picked
    return (range[0] + rand()%(range[1]-range[0] + 1));
}



/* print function
 */
inline void range_addr::print() const {
    cout<< get_str() <<endl;
}

inline string range_addr::get_str() const {
    stringstream ss;
    ss<<range[0] << ":" << range[1];
    return ss.str();
}

#endif

