#ifndef MIC_RULE_TREE_H
#define MIC_RULE_TREE_H

#include "stdafx.h"
#include "Address.hpp"
#include "Rule.hpp"
#include "RuleList.h"
#include <deque>

using std::vector;
class f_node
{
public:
    vector<range_addr> intervals;
    vector<f_node*> edges;

    f_node();
    f_node(uint32_t);
    f_node(const vector<range_addr> &);
    f_node(const range_addr & );

    bool insert(const r_rule &, uint32_t );
    std::string get_str();
private:
    void copy_node_son(f_node *, f_node * );
};
/*
class f_node_e:public f_node{
	public:
		unsigned short action;
};
*/
class m_rule_tree
{
public:
    rule_list * rList;
    f_node * root;
    vector<uint32_t> redid;

    m_rule_tree();
    m_rule_tree(rule_list *);

    void print(std::string);
    bool insert_rule(const r_rule &);
    bool insert_rule(const p_rule &);
    f_node * search_node ( const addr_5tup &);

private:
    friend void del_node(f_node *);
public:
    ~m_rule_tree();
};

class f_node_s
{
public:
    range_addr interval;
    vector<f_node_s*> edges;

};

class f_node_se:public f_node_s
{
public:
    unsigned short action;
};
#endif
