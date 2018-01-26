#include "MicRuleTree.h"

using std::vector;
using std::deque;
using std::cout;
using std::endl;
using std::string;
using std::stringstream;
using std::ofstream;

typedef vector<range_addr>::iterator IntIter;
typedef vector<f_node *>::iterator EdgeIter;

// f_node
f_node::f_node() {}

f_node::f_node(uint32_t dim) {
    if (dim < 2) {
        intervals.insert(intervals.end(), range_addr(0, ~uint32_t(0)));
    } else {
        intervals.insert(intervals.end(), range_addr(0, (~uint32_t(0))>>16));
    }
}

f_node::f_node(const vector<range_addr> & rav) {
    intervals = rav;
    edges.clear();
}

f_node::f_node(const range_addr & ra) {
    intervals.insert(intervals.end(), ra);
    edges.clear();
}

void print_vector(vector<range_addr> & interv) {
    for (IntIter iter = interv.begin(); iter != interv.end(); iter++)
        cout << iter->get_str() << "\t";
    cout <<endl;
}

/* function: insert
 * Insert rule to construct sons
 */
void del_node(f_node *);
bool f_node::insert(const r_rule & rule, uint32_t dim) {
    if ( dim == 4 )
        return false;

    range_addr ra = rule.addrs[dim];
    vector <range_addr> res(1, ra);
    bool effective = false;
    for (uint32_t idx = 0; idx != edges.size(); idx++) {
        vector<range_addr> to_minus;
        f_node *ePtr = edges[idx];
        bool include = true;
        for (IntIter iter_i = edges[idx]->intervals.begin(); iter_i != edges[idx]->intervals.end(); iter_i++) {
            range_addr cap = ra.intersect(*iter_i);
            if (cap.range[0] > cap.range[1]) // not intersect
                continue;
            if (!(cap.range[0] == iter_i->range[0] && cap.range[1] == iter_i->range[1])) { // not include
                include = false;
            }
            to_minus.insert(to_minus.end(), cap);
        }

        if ((!include) && (!to_minus.empty())) {
            f_node* temp = new f_node(to_minus);
            copy_node_son(ePtr, temp);
            effective = temp->insert(rule, dim+1); // revert back
            if (effective) {
                edges.insert(edges.end(), temp);
                ePtr->intervals = minus_rav(ePtr->intervals, to_minus);
            } else {
                del_node(temp);
            }
        } else
            effective = (ePtr)->insert(rule, dim+1);

        res = minus_rav(res, to_minus);
    }

    if(!res.empty()) {
        f_node* temp = new f_node();
        temp->intervals = res;
        edges.insert(edges.end(), temp);
        for (uint32_t i = dim+1; i < 4; i++) {
            f_node * temp1 = new f_node(rule.addrs[i]);
            temp->edges.insert(temp->edges.end(), temp1);
            temp = temp1;
        }
        return true;
    }
    return effective;
};

void f_node::copy_node_son(f_node * target, f_node * node) {
    for (EdgeIter iter = target->edges.begin(); iter != target->edges.end(); iter++) {
        f_node * temp = new f_node((*iter)->intervals);
        node->edges.insert(node->edges.end(), temp);
        copy_node_son(*iter, temp);
    }

}

string f_node::get_str() {
    stringstream ss;

    ss<<"node:"<<endl;
    for (EdgeIter iter = edges.begin(); iter != edges.end(); iter++) {
        for (IntIter iter1 = (*iter)->intervals.begin(); iter1 != (*iter)->intervals.end(); iter1++) {
            ss<<(*iter1).get_str()<<"\t";
        }
        ss<<endl;
    }
    return ss.str();
}

// m_rule_tree
m_rule_tree::m_rule_tree() {
    rList = NULL;
    root = new f_node(0);
}

m_rule_tree::m_rule_tree(rule_list * rL) {
    rList =rL;
    root = new f_node(0);
    for (uint32_t i = 0; i < rL->list.size(); i++) {
        insert_rule(rL->list[i]);
    }
}

m_rule_tree::~m_rule_tree() {
    if (root != NULL)
        del_node(root);
}

bool m_rule_tree::insert_rule(const p_rule & rule) {
    return insert_rule(r_rule(rule));
}

bool m_rule_tree::insert_rule(const r_rule & rule) {
    bool mod = false;
    root->insert(rule, 0);
    return mod;
}

f_node * m_rule_tree::search_node(const addr_5tup & ad) {
    f_node * temp = root;
    EdgeIter iter_e;
    for (uint32_t i = 0; i < 4; i++) {
        for (iter_e = temp->edges.begin(); iter_e != temp->edges.end(); iter_e++) {
            bool hit_int = false;
            for (IntIter iter_i = (*iter_e)->intervals.begin(); iter_i != (*iter_e)->intervals.end(); iter_e++) {
                if (iter_i->hit(ad.addrs[i])) {
                    hit_int = true;
                    break;
                }
            }
            if (hit_int)
                break;
        }
        if (iter_e != temp->edges.end())
            temp = *iter_e;
        else
            return NULL;
    }
    return temp;
}

void m_rule_tree::print(string str) {
    ofstream ff(str);
    deque<f_node *> que;
    que.push_back(root);
    while (!que.empty()) {
        f_node * deal = *(que.begin());
        ff<<deal->get_str()<<endl;
        for (EdgeIter iter = deal->edges.begin(); iter != deal->edges.end(); iter++) {
            que.push_back(*iter);
        }
        que.pop_front();
    }

    ff.close();
}

void del_node(f_node * node) {
    for (EdgeIter iter = node->edges.begin(); iter != node->edges.end(); iter++)
        del_node(*iter);
    delete node;
}
