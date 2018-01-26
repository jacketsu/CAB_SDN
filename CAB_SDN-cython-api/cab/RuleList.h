#ifndef RULELIST_H
#define RULELIST_H

#include "stdafx.h"
#include "Address.hpp"
#include "Rule.hpp"
#include <unordered_map>

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/adjacency_iterator.hpp>


class rule_list {
public:
    std::vector<p_rule> list;
    std::unordered_map <uint32_t, std::vector<uint32_t> > dep_map;
    std::unordered_map <uint32_t, std::vector<uint32_t> > cover_map;
    std::vector<size_t> occupancy;

    rule_list();
    rule_list(std::string & filename, bool test_bed = false);

    // for dependency set
    void obtain_dep();

    // for micro set
    r_rule get_micro_rule (const addr_5tup &);
    r_rule get_micro_rule_split (const addr_5tup &);
    int linear_search(const addr_5tup &);

    // for covering set #
    // TBD
private:
    typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS> depDAG;
    typedef boost::graph_traits<depDAG>::vertex_descriptor vertex_descriptor;
    typedef boost::graph_traits<depDAG>::vertex_iterator vertex_iterator;
    typedef boost::graph_traits<depDAG>::adjacency_iterator adjacency_iterator;//jiaren
    depDAG depDag;

public:
    void createDAG();
    void obtain_cover();

    void clearHitFlag();

    void rule_dep_analysis();
    void print(const std::string &);
};
#endif
