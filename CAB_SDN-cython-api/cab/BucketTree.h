#ifndef BUCKET_TREE
#define BUCKET_TREE

#include "stdafx.h"
#include "Address.hpp"
#include "Rule.hpp"
#include "RuleList.h"
#include "Bucket.h"
#include <cmath>
#include <set>
#include <deque>
#include <list>
// #include <boost/iostreams/filtering_stream.hpp>
// #include <boost/iostreams/filter/gzip.hpp>
// #include <boost/filesystem.hpp>

class bucket_tree {
  // private:
  //   boost::log::sources::logger bTree_log;
  public:
    bucket * root;
    rule_list * rList;
    uint32_t thres_soft;
    uint32_t thres_hard;
    uint32_t pa_rule_no;
    std::set<uint32_t> pa_rules;
    int tree_depth;

    // for debug
    bool debug;

    // HyperCut related
    size_t max_cut_per_layer;
    double slow_prog_perc;

    std::vector<std::vector<size_t> > candi_split;

  public:
    bucket_tree();
    bucket_tree(rule_list &, uint32_t, bool test_bed = false, size_t = 0);
    ~bucket_tree();

    std::pair<bucket *, int> search_bucket(const addr_5tup &, bucket* ) const;
    bucket * search_bucket_seri(const addr_5tup &, bucket* ) const;
    void check_static_hit(const b_rule &, bucket*, std::set<size_t> &, size_t &);
    void pre_alloc();
    void dyn_adjust();
    void cal_tree_depth(bucket *, int = 0);

  private:
    // static related
    void gen_candi_split(bool, size_t = 2);
    void splitNode_fix(bucket * = NULL);
    void INOallocDet(bucket *, std::vector<uint32_t> &) const;
    void INOpruning(bucket *);
    void delNode(bucket *);

  public:
    // dynamic related
    void merge_bucket(bucket*);
    void merge_bucket_CPLX_test(bucket*);
    //void regi_occupancy(bucket*, std::deque <bucket*> &); // deprecated Apr. 24
    void rec_occupancy(bucket*, std::list <bucket*> &);
    void repart_bucket();
    void repart_bucket_CPLX_test(int);

    void print_bucket(std::ofstream &, bucket *, bool); // const

  public:
    // test use
    // void search_test(const string &) ;
    void static_traf_test(const string &);
    void evolving_traf_test_dyn(const std::vector<b_rule> &, const std::vector<b_rule> &, std::ofstream &, double,  pair<size_t, size_t> & , size_t &);
    void evolving_traf_test_stat(const std::vector<b_rule> &, const std::vector<b_rule> &, std::ofstream &);
    void print_tree(const string & filename, bool details = false); // const

};

#endif


