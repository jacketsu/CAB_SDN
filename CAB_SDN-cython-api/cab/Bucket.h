#ifndef BUCKET
#define BUCKET

#include "stdafx.h"
#include "Address.hpp"
#include "Rule.hpp"
#include "RuleList.h"
#include <set>

class bucket: public b_rule {
  private:
    // static boost::log::sources::logger lg;
    static void logger_init();

  public:
    std::vector<bucket*> sonList; 		// List of son nodes
    std::vector<uint32_t> related_rules;	// IDs of related rules in the bucket
    uint32_t cutArr[4];			// how does this node is cut.  e.g. [2,3,0,0] means 2 cuts on dim 0, 3 cuts on dim 1
    bool hit;
    bucket * parent;
    size_t max_gain;
    size_t repart_level;

  public:
    bucket();
    bucket(const bucket &);
    bucket(const string &, const rule_list *);
    std::pair<double, size_t> split(const std::vector<size_t> &, rule_list *);
    int reSplit(const std::vector<size_t> &, rule_list *, bool = false);
    void reSplit(const std::vector<std::vector<size_t> >&, rule_list *, size_t);
    std::vector<size_t> unq_comp(rule_list *);

    void cleanson();
    void clearHitFlag();
    string get_str() const;
};

#endif

