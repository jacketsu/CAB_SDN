#ifndef CACHE_FLOW_H
#define CACHE_FLOW_H

#include "stdafx.h"
#include "Address.hpp"
#include "Rule.hpp"
#include "RuleList.h"
#include <algorithm>
#include <unordered_set>

using std::set;
using std::unordered_set;
using std::sort;

class rule_info {
public:
    uint32_t idx;
    bool is_cover = false;
    vector<uint32_t> assoc_rules;  // maintain sorted
    int assoc_weight;
    int comb_cost;

public:
    rule_info(uint32_t i, rule_list * rL, bool is_cover) {
        idx = i;
        is_cover = is_cover;

        if (is_cover) {
            assoc_rules = rL->cover_map[i];
        } else {
            assoc_rules = rL->dep_map[i];
        }

        for(auto j : assoc_rules) {
            assoc_weight += rL->list[j].weight;
        }

        comb_cost = (assoc_weight + rL->list[i].weight) /
                    (assoc_rules.size() + 1);
    }

    bool operator< (const rule_info & another) const {
        return comb_cost < another.comb_cost;
    };

    void update_cost(const vector<uint32_t> & to_delete, rule_list * rL) {
        // rules to evict
        vector<uint32_t> to_del(assoc_rules.size()+to_delete.size());
        auto iter = set_union(assoc_rules.begin(), assoc_rules.end(),
                              to_delete.begin(), to_delete.end(), to_del.begin());
        to_del.resize(iter-to_del.begin());

        // update associated rules
        auto iter_d = to_del.begin();
        auto iter_b = assoc_rules.begin();

        vector<uint32_t> new_assoc(assoc_rules.size()-to_del.size());
        int i = 0;
        while(iter_d != to_del.end()) {
            if (*iter_b == *iter_d) {
                iter_b++;
                iter_d++;
            } else {
                new_assoc[i] = *iter_b;
                iter_b++;
            }
        }
        assoc_rules = new_assoc;

        for (auto del_idx : to_del) {
            assoc_weight -= rL->list[del_idx].weight;
        }

        assert(assoc_weight >= 0);
        comb_cost = (assoc_weight + rL->list[i].weight) /
                    (assoc_rules.size() + 1);
    };
};

struct cached_info {
    int idx;
    bool to_cntl = false;

    cached_info(int idx, bool cntl):idx(idx),to_cntl(cntl) {};

    bool operator< (const cached_info & another) {
        return idx < another.idx;
    }
};

class mixed_set {
public:
    set<cached_info> to_cache_set;

private:
    int total_memory;
    rule_list * rList;

public:
    mixed_set(int memory, rule_list * rL) {
        total_memory = memory;
        rList = rL;
    }

    void cal_mixed_set() {
        vector<rule_info> candi_heap;

        for(int i = 0; i < rList->list.size(); ++i) {
            candi_heap.push_back(rule_info(i, rList, true));
            candi_heap.push_back(rule_info(i, rList, false));
        }

        while (true) {
            std::make_heap(candi_heap.begin(), candi_heap.end());
            rule_info to_cache = candi_heap[candi_heap.size()-1];
            candi_heap.erase(candi_heap.begin() + (candi_heap.size() - 1));

            unordered_set<int> assoc_set;
            for (auto assoc_idx : to_cache.assoc_rules) {
                assoc_set.insert(assoc_idx);
            }

            if (!to_cache.is_cover) {
                for (auto candiIter = candi_heap.begin(); candiIter != candi_heap.end();) {
                    if (candiIter->idx == to_cache.idx) { // delete the same cover set
                        candiIter = candi_heap.erase(candiIter);
                        continue;
                    }
                    if (assoc_set.find(candiIter->idx) != assoc_set.end()) { // erase dep rule
                        candiIter = candi_heap.erase(candiIter);
                    } else { // update cost
                        candiIter->update_cost(to_cache.assoc_rules, rList); // assoc
                        vector<uint32_t> one_rule(1, to_cache.idx);
                        candiIter->update_cost(one_rule, rList); // itself
                        candiIter++;
                    }
                }
            } else {
                for (auto candiIter = candi_heap.begin(); candiIter != candi_heap.end();) {
                    if (candiIter->idx == to_cache.idx) { // delete the same dep set
                        candiIter = candi_heap.erase(candiIter);
                        continue;
                    } else { // update cost
                        candiIter->update_cost(to_cache.assoc_rules, rList);
                        vector<uint32_t> one_rule(1, to_cache.idx);
                        candiIter->update_cost(one_rule, rList); // itself
                        candiIter++;
                    }
                }
            }

            // calculate cost increment 
            int memory_used = to_cache.assoc_rules.size();
            if (memory_used + to_cache_set.size() > total_memory)
                break;

            for (auto candi_idx : to_cache.assoc_rules) {
                auto res = to_cache_set.insert(cached_info(candi_idx, true));
                assert(res.second);
            }
            auto res = to_cache_set.insert(cached_info(to_cache.idx, false));
            if (!res.second){
                res.first->to_cntl = false;
            }
            else{
                memory_used++;
            }
        }

    }
};
#endif
