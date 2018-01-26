#include "BucketTree.h"

typedef vector<uint32_t>::iterator Iter_id;
typedef vector<bucket*>::iterator Iter_son;

// namespace fs = boost::filesystem;
// namespace io = boost::iostreams;

using std::set;
using std::list;
using std::ifstream;
using std::ofstream;

// ---------- bucket_tree ------------
bucket_tree::bucket_tree() {
    root = NULL;
    thres_soft = 0;
    tree_depth = 0;
}
//jiaren20161117: test_bed -> bIs2tup
bucket_tree::bucket_tree(rule_list & rL, uint32_t thr, bool bIs2tup, size_t pa_no ) {
    thres_hard = thr;
    thres_soft = thr*2;
    rList = &rL;
    root = new bucket(); // full address space
    for (uint32_t i = 0; i < rL.list.size(); i++)
        root->related_rules.insert(root->related_rules.end(), i);

    gen_candi_split(bIs2tup);
    splitNode_fix(root);

    pa_rule_no = pa_no;
    tree_depth = 0;
}

bucket_tree::~bucket_tree() {
    delNode(root);
}

pair<bucket *, int> bucket_tree::search_bucket(const addr_5tup& packet, bucket * buck) const {
    if (!buck->sonList.empty()) {
        size_t idx = 0;
        for (int i = 3; i >= 0; --i) {
            if (buck->cutArr[i] != 0) {
                idx = (idx << buck->cutArr[i]);
                size_t offset = (packet.addrs[i] - buck->addrs[i].pref);
                offset = offset/((~(buck->addrs[i].mask) >> buck->cutArr[i]) + 1);
                idx += offset;
            }
        }
        assert (idx < buck->sonList.size());
        return search_bucket(packet, buck->sonList[idx]);
    } else {
        buck->hit = true;
        int rule_id = -1;

        for (auto iter = buck->related_rules.begin(); iter != buck->related_rules.end(); ++iter) {
            if (rList->list[*iter].packet_hit(packet)) {
                rList->list[*iter].hit = true;
                rule_id = *iter;
                break;
            }
        }
        return std::make_pair(buck, rule_id);
    }
}

bucket * bucket_tree::search_bucket_seri(const addr_5tup& packet, bucket * buck) const {
    if (buck->sonList.size() != 0) {
        for (auto iter = buck->sonList.begin(); iter != buck->sonList.end(); ++iter)
            if ((*iter)->packet_hit(packet))
                return search_bucket_seri(packet, *iter);
        return NULL;
    } else {
        return buck;
    }
}

void bucket_tree::check_static_hit(const b_rule & traf_block, bucket* buck, set<size_t> & cached_rules, size_t & buck_count) {
    if (buck->sonList.empty()) { // bucket
        bool this_buck_hit = false;
        // a bucket is hit only when at least one rule is hit
        for (auto iter = buck->related_rules.begin(); iter != buck->related_rules.end(); ++iter) {
            if (traf_block.match_rule(rList->list[*iter])) {
                this_buck_hit = true;
                break;
            }
        }

        if (this_buck_hit) { // this bucket is hit
            for (auto iter = buck->related_rules.begin(); iter != buck->related_rules.end(); ++iter) {
                cached_rules.insert(*iter);
                if (traf_block.match_rule(rList->list[*iter])) {
                    rList->list[*iter].hit = true;
                }
            }
            ++buck_count;
            buck->hit = true; // only matching at least one rule is considered a bucket hit
        }
    } else {
        for (auto iter = buck->sonList.begin(); iter != buck->sonList.end(); ++iter) {

            if ((*iter)->overlap(traf_block))
                check_static_hit(traf_block, *iter, cached_rules, buck_count);
        }
    }
}


void bucket_tree::gen_candi_split(bool bIs2tup, size_t cut_no) {
    if (bIs2tup) {
        vector<size_t> base(4,0);
        for (size_t i = 0; i <= cut_no; ++i) {
            base[0] = i;
            base[1] = cut_no - i;
            candi_split.push_back(base);
        }
    } else {
        if (cut_no == 0) {
            vector<size_t> base(4,0);
            candi_split.push_back(base);
        } else {
            gen_candi_split(bIs2tup, cut_no-1);
            vector< vector<size_t> > new_candi_split;
            if (cut_no > 1)
                new_candi_split = candi_split;

            for (auto iter = candi_split.begin(); iter != candi_split.end(); ++iter) {
                for (size_t i = 0; i < 4; ++i) {
                    vector<size_t> base = *iter;
                    ++base[i];
                    new_candi_split.push_back(base);
                }
            }
            candi_split = new_candi_split;
        }
    }
}

void bucket_tree::splitNode_fix(bucket * ptr) {
    double cost = ptr->related_rules.size();
    if (cost < thres_soft)
        return;

    pair<double, size_t> opt_cost = std::make_pair(ptr->related_rules.size(), ptr->related_rules.size());
    vector<size_t> opt_cut;

    for (auto iter = candi_split.begin(); iter != candi_split.end(); ++iter) {
        auto cost = ptr->split(*iter, rList);

        if (cost.first < 0)
            continue;

        if (cost.first < opt_cost.first || ((cost.first == opt_cost.first) && (cost.second < opt_cost.second))) {
            opt_cut = *iter;
            opt_cost = cost;
        }
    }

    if (opt_cut.empty()) {
        ptr->cleanson();
        return;
    } else {
        ptr->split(opt_cut, rList);
        for (size_t i = 0; i < 4; ++i)
            ptr->cutArr[i] = opt_cut[i];

        for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter)
            splitNode_fix(*iter);
    }
}

void bucket_tree::pre_alloc() {
    vector<uint32_t> rela_buck_count(rList->list.size(), 0);
    INOallocDet(root, rela_buck_count);

    for (uint32_t i = 0; i< pa_rule_no; i++) {
        uint32_t count_m = 0;
        uint32_t idx;
        for (uint32_t i = 0; i < rela_buck_count.size(); i++) {
            if(rela_buck_count[i] > count_m) {
                count_m = rela_buck_count[i];
                idx = i;
            }
        }
        rela_buck_count[idx] = 0;
        pa_rules.insert(idx);
    }

    INOpruning(root);
}

void bucket_tree::dyn_adjust() {
    merge_bucket(root);
    print_tree("../para_src/tree_merge.dat");
    repart_bucket();
    rList->clearHitFlag();
}


void bucket_tree::INOallocDet (bucket * bk, vector<uint32_t> & rela_buck_count) const {
    for (Iter_id iter = bk->related_rules.begin(); iter != bk->related_rules.end(); iter++) {
        rela_buck_count[*iter] += 1;
    }
    for (Iter_son iter_s = bk->sonList.begin(); iter_s != bk->sonList.end(); iter_s ++) {
        INOallocDet(*iter_s, rela_buck_count);
    }
    return;
}

void bucket_tree::INOpruning (bucket * bk) {
    for (Iter_id iter = bk->related_rules.begin(); iter != bk->related_rules.end(); ) {
        if (pa_rules.find(*iter) != pa_rules.end())
            bk->related_rules.erase(iter);
        else
            ++iter;
    }

    if (bk->related_rules.size() < thres_hard) { // if after pruning there's no need to split
        for (Iter_son iter_s = bk->sonList.begin(); iter_s != bk->sonList.end(); iter_s++) {
            delNode(*iter_s);
        }
        bk->sonList.clear();
        return;
    }

    for (Iter_son iter_s = bk->sonList.begin(); iter_s != bk->sonList.end(); iter_s ++) {
        INOpruning(*iter_s);
    }
    return;
}

void bucket_tree::delNode(bucket * ptr) {
    for (Iter_son iter = ptr->sonList.begin(); iter!= ptr->sonList.end(); iter++) {
        delNode(*iter);
    }
    delete ptr;
}

void bucket_tree::cal_tree_depth(bucket * ptr, int count) {
    for (Iter_son iter = ptr->sonList.begin(); iter != ptr->sonList.end(); iter++) {
        cal_tree_depth(*iter, count+1);
    }
    if (count > tree_depth)
        tree_depth = count;
}

// dynamic related
void bucket_tree::merge_bucket(bucket * ptr) { // merge using back order search
    if (!ptr->sonList.empty()) {
        for (auto iter = ptr->sonList.begin(); iter!= ptr->sonList.end(); ++iter) {
            merge_bucket(*iter);
        }
    } else
        return;

    bool at_least_one_hit = false;

    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter) {  // don't merge if all empty
        if ((*iter)->hit)
            at_least_one_hit = true;
        else {
            if (!(*iter)->related_rules.empty())
                return;
        }
    }

    if (!at_least_one_hit)
        return;

    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter) // remove the sons.
        delete *iter;
    ptr->sonList.clear();
    ptr->hit = true;
}

void bucket_tree::merge_bucket_CPLX_test(bucket * ptr) { // merge using back order search
    if (!ptr->sonList.empty()) {
        for (auto iter = ptr->sonList.begin(); iter!= ptr->sonList.end(); ++iter) {
            merge_bucket_CPLX_test(*iter);
        }
    } else
        return;
    /********   Junan: added to limit merge  *********/
    if (ptr->related_rules.size() >= thres_soft*2)
        return;

    bool at_least_one_hit = false;

    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter) {  // don't merge if all empty
        if ((*iter)->hit)
            at_least_one_hit = true;
        else {
            if (!(*iter)->related_rules.empty())
                return;
        }
    }

    if (!at_least_one_hit)
        return;

    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter) // remove the sons.
        delete *iter;
    ptr->sonList.clear();
    ptr->hit = true;
}
/*
void bucket_tree::regi_occupancy(bucket * ptr, deque <bucket *>  & hitBucks) {
    if (ptr->sonList.empty() && ptr->hit) {
        ptr->hit = false;  // clear the hit flag
        hitBucks.push_back(ptr);
        for (auto iter = ptr->related_rules.begin(); iter != ptr->related_rules.end(); ++iter) {
            ++rList->occupancy[*iter];
        }
    }
    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter)
        regi_occupancy(*iter, hitBucks);
}*/

void bucket_tree::rec_occupancy(bucket * ptr, list<bucket *> & hitBucks) {
    if (ptr->sonList.empty() && ptr->hit) {
        ptr->hit = false; // clear the hit flag
        ptr->repart_level = 0;
        hitBucks.push_back(ptr);
        for (auto iter = ptr->related_rules.begin(); iter != ptr->related_rules.end(); ++iter) {
            ++rList->occupancy[*iter];
        }
    }
    for (auto iter = ptr->sonList.begin(); iter != ptr->sonList.end(); ++iter)
        rec_occupancy(*iter, hitBucks);
}

void bucket_tree::repart_bucket() {
    // deque<bucket *> proc_line;  // Apr.25 updated
    list<bucket *> proc_line;
    rec_occupancy(root, proc_line);

    size_t suc_counter = 0;
    auto proc_iter = proc_line.begin();

    while (!proc_line.empty()) {
        while(true) {
            if (suc_counter == proc_line.size())
                return;

            if (proc_iter == proc_line.end())   // cycle
                proc_iter = proc_line.begin();

            bool found = false;
            for (auto rule_iter = (*proc_iter)->related_rules.begin();
                    rule_iter != (*proc_iter)->related_rules.end();
                    ++rule_iter) {
                if (rList->occupancy[*rule_iter] == 1) {
                    found = true;
                    break;
                }
            }

            if (found)
                break;
            else {
                ++proc_iter;
                ++suc_counter; // suc_counter;
            }

        }

        bucket* to_proc_bucket = *proc_iter;

        vector<size_t> opt_cut;
        int opt_gain = -1; // totally greedy: no gain don't partition

        for (auto iter = candi_split.begin(); iter != candi_split.end(); ++iter) {
            int gain = to_proc_bucket->reSplit(*iter, rList);
            if (gain > opt_gain) {
                opt_gain = gain;
                opt_cut = *iter;
            }
        }

        if (opt_cut.empty()) {
            to_proc_bucket->cleanson();
            ++proc_iter; // keep the bucket
            ++suc_counter;
        } else {
            //BOOST_LOG(bTree_log) << "success";
            proc_iter = proc_line.erase(proc_iter); // delete the bucket
            suc_counter = 0;
            to_proc_bucket->reSplit(opt_cut, rList, true);

            for (size_t i = 0; i < 4; ++i)
                to_proc_bucket->cutArr[i] = opt_cut[i];

            for (auto iter = to_proc_bucket->sonList.begin(); // push son
                    iter != to_proc_bucket->sonList.end(); // immediate proc
                    ++iter) {
                bool son_hit = false;
                for(auto r_iter = (*iter)->related_rules.begin(); r_iter != (*iter)->related_rules.end(); ++r_iter) {
                    if (rList->list[*r_iter].hit) {
                        son_hit = true;
                        break;
                    }
                }

                if (son_hit) {
                    proc_iter = proc_line.insert(proc_iter, *iter);
                }
            }
        }
    }
}

void bucket_tree::repart_bucket_CPLX_test(int level) {
    // deque<bucket *> proc_line;  // Apr.25 updated
    list<bucket *> proc_line;
    rec_occupancy(root, proc_line);

    size_t suc_counter = 0;
    auto proc_iter = proc_line.begin();

    while (!proc_line.empty()) {
        while(true) {
            if (suc_counter == proc_line.size())
                return;

            if (proc_iter == proc_line.end())   // cycle
                proc_iter = proc_line.begin();

            bool found = false;
            for (auto rule_iter = (*proc_iter)->related_rules.begin();
                    rule_iter != (*proc_iter)->related_rules.end();
                    ++rule_iter) {
                if (rList->occupancy[*rule_iter] == 1) {
                    found = true;
                    break;
                }
            }

            if (found)
                break;
            else {
                ++proc_iter;
                ++suc_counter; // suc_counter;
            }

        }

        bucket* to_proc_bucket = *proc_iter;

        /*******    Junan: check depth to limit maximum split   *********/
        if ( (to_proc_bucket->repart_level >= level) &&
                (to_proc_bucket->related_rules.size() < thres_hard) ) {
            proc_iter = proc_line.erase(proc_iter); // delete the bucket
            suc_counter = 0;
            continue;
        }

        vector<size_t> opt_cut;
        int opt_gain = -1; // totally greedy: no gain don't partition

        for (auto iter = candi_split.begin(); iter != candi_split.end(); ++iter) {
            int gain = to_proc_bucket->reSplit(*iter, rList);
            if (gain > opt_gain) {
                opt_gain = gain;
                opt_cut = *iter;
            }
        }
        /*******    Junan: force to cut     **********/
        size_t cut[4] = {1,1,0,0};
        for (size_t i = 0; i < 4; i++)
            opt_cut[i] = cut[i];

        if (opt_cut.empty()) {
            to_proc_bucket->cleanson();
            ++proc_iter; // keep the bucket
            ++suc_counter;
        } else {
            //BOOST_LOG(bTree_log) << "success";
            proc_iter = proc_line.erase(proc_iter); // delete the bucket
            suc_counter = 0;
            to_proc_bucket->reSplit(opt_cut, rList, true);

            for (size_t i = 0; i < 4; ++i)
                to_proc_bucket->cutArr[i] = opt_cut[i];

            for (auto iter = to_proc_bucket->sonList.begin(); // push son
                    iter != to_proc_bucket->sonList.end(); // immediate proc
                    ++iter) {
                /*******    Junan: record repart levels to limit repartition    *******/
                (*iter)->repart_level = to_proc_bucket->repart_level + 1;

                bool son_hit = false;
                for(auto r_iter = (*iter)->related_rules.begin(); r_iter != (*iter)->related_rules.end(); ++r_iter) {
                    if (rList->list[*r_iter].hit) {
                        son_hit = true;
                        break;
                    }
                }
                /*******    Junan: if son bucket contain rules then add to proc_line    *******/
                if (!(*iter)->related_rules.empty())
                    son_hit = true;

                if (son_hit) {
                    /*******    Junan: didn't increase occupancy in reSplit(). so do it here    *******/
                    for (auto iter_id = (*iter)->related_rules.begin();
                            iter_id != (*iter)->related_rules.end(); ++iter_id) {
                        ++rList->occupancy[*iter_id];
                    }
                    proc_iter = proc_line.insert(proc_iter, *iter);
                }
            }
        }
    }
}


void bucket_tree::print_bucket(ofstream & in, bucket * bk, bool detail) { // const
    if (bk->sonList.empty()) {
        in << bk->get_str() << endl;
        if (detail) {
            in << "re: ";
            for (Iter_id iter = bk->related_rules.begin(); iter != bk->related_rules.end(); iter++) {
                in << *iter << " ";
            }
            in <<endl;
        }

    } else {
        for (Iter_son iter = bk->sonList.begin(); iter != bk->sonList.end(); iter++)
            print_bucket(in, *iter, detail);
    }
    return;
}



/* TEST USE Functions
 *
 */

// void bucket_tree::search_test(const string & tracefile_str) {
//     io::filtering_istream in;
//     in.push(io::gzip_decompressor());
//     ifstream infile(tracefile_str);
//     in.push(infile);
// 
//     string str;
//     cout << "Start search testing ... "<< endl;
//     size_t cold_packet = 0;
//     size_t hot_packet = 0;
//     while (getline(in, str)) {
//         addr_5tup packet(str, false);
//         auto result = search_bucket(packet, root);
//         if (result.first->related_rules.size() < 10) {
//             ++cold_packet;
//         } else {
//             ++hot_packet;
//         }
// 
//         if (result.first != (search_bucket_seri(packet, root))) {
//             cout << "Within bucket error: packet: " << str;
//             cout << "search_buck   res : " << result.first->get_str();
//             cout << "search_buck_s res : " << result.first->get_str();
//         }
//         if (result.second != rList->linear_search(packet)) {
//             if (pa_rules.find(rList->linear_search(packet)) == pa_rules.end()) { // not pre-allocated
//                 cout << "Search rule error: packet:" << str;
//                 if (result.second > 0)
//                     cout << "search_buck res : " << rList->list[result.second].get_str();
//                 else
//                     cout << "search_buck res : " << "None";
// 
//                 cout << "linear_sear res : " << rList->list[rList->linear_search(packet)].get_str();
//             }
//         }
//     }
// 
//     cout << "hot packets: "<< hot_packet;
//     cout << "cold packets: "<< cold_packet;
//     cout << "Search testing finished ... " << endl;
// }

void bucket_tree::static_traf_test(const string & file_str) {
    ifstream file(file_str);
    size_t counter = 0;
    set<size_t> cached_rules;
    size_t buck_count = 0;

    debug = false;
    for (string str; getline(file, str); ++counter) {
        int idx = str.find_last_of("\t");
        size_t r_exp = stoul(str.substr(idx));
        // vector<string> temp;
        // boost::split(temp, str, boost::is_any_of("\t"));
        // size_t r_exp = boost::lexical_cast<size_t>(temp.back());
        if (r_exp > 40) {
            --counter;
            continue;
        }

        b_rule traf_blk(str);
        check_static_hit(traf_blk, root, cached_rules, buck_count);
        if (counter > 80)
            break;
    }
    cout << "Cached: " << cached_rules.size() << " rules, " << buck_count << " buckets " <<endl;

    dyn_adjust();
    print_tree("../para_src/tree_split.dat");

    buck_count = 0;
    rList->clearHitFlag();
    cached_rules.clear();

    counter = 0;
    file.seekg(std::ios::beg);
    for (string str; getline(file, str); ++counter) {
        int idx = str.find_last_of("\t");
        size_t r_exp = stoul(str.substr(idx));
        // vector<string> temp;
        // boost::split(temp, str, boost::is_any_of("\t"));
        // size_t r_exp = boost::lexical_cast<size_t>(temp.back());
        if (r_exp > 40) {
            --counter;
            continue;
        }

        b_rule traf_blk(str);
        check_static_hit(traf_blk, root, cached_rules, buck_count);
        if (counter > 80)
            break;
    }


    list<bucket *> proc_line;
    rec_occupancy(root, proc_line);

    size_t unused_count = 0;
    stringstream ss;
    for (auto iter = cached_rules.begin(); iter != cached_rules.end(); ++iter) {
        if (!rList->list[*iter].hit) {
            ++unused_count;
            ss<<*iter << "("<< rList->occupancy[*iter]<<") ";
        }
    }
    cout << "Unused rules: "<<ss.str();

    cout << "Cached: " << cached_rules.size() << " rules (" << unused_count << ") " << buck_count << " buckets " <<endl;

}

void bucket_tree::evolving_traf_test_dyn(const vector<b_rule> & prev, const vector<b_rule> & after, ofstream & rec_file, double threshold, pair<size_t, size_t> & last_overhead, size_t & adj_time) {
    vector <b_rule> current = prev;
    bool to_adjust = true;
    for (size_t counter = 0; counter < prev.size(); ++counter) {
        set<size_t> cached_rules;
        size_t buck_count = 0;

        if (to_adjust) { // dyn_adj
            for (auto iter = current.begin(); iter != current.end(); ++iter) {
                check_static_hit(*iter, root, cached_rules, buck_count);
            }
            dyn_adjust();
            cached_rules.clear();
            buck_count = 0;
            ++adj_time;
        }

        for (auto iter = current.begin(); iter != current.end(); ++iter) {
            check_static_hit(*iter, root, cached_rules, buck_count);
        }

        size_t unused_count = 0;
        for (auto iter = cached_rules.begin(); iter != cached_rules.end(); ++iter) {
            if (!rList->list[*iter].hit) {
                ++unused_count;
            }
        }

        cout << "Dyn Cached: " << cached_rules.size() << " rules (" << unused_count << " unused) " << buck_count << " buckets ";

        rec_file << cached_rules.size() << "\t" << buck_count << "\t" << cached_rules.size() + buck_count<<endl;

        if (to_adjust) {
            cout << "Adjust here: " << counter;
            last_overhead.first = unused_count;
            last_overhead.second = buck_count;
            to_adjust = false;
        } else {
            if (unused_count < last_overhead.first)
                last_overhead.first = unused_count;
            else if (unused_count > threshold * last_overhead.first)
                to_adjust = true;
            if (buck_count < last_overhead.second)
                last_overhead.second = buck_count;
            else if (buck_count > threshold * last_overhead.second)
                to_adjust = true;
        }

        current[counter] = after[counter]; // evolve traffic
        root->clearHitFlag();
        rList->clearHitFlag();
    }
}

void bucket_tree::evolving_traf_test_stat(const vector<b_rule> & prev, const vector<b_rule> & after, ofstream & rec_file) {
    vector <b_rule> current = prev;
    for (size_t counter = 0; counter < prev.size(); ++counter) {
        set<size_t> cached_rules;
        size_t buck_count = 0;

        for (auto iter = current.begin(); iter != current.end(); ++iter) {
            check_static_hit(*iter, root, cached_rules, buck_count);
        }

        size_t unused_count = 0;
        for (auto iter = cached_rules.begin(); iter != cached_rules.end(); ++iter) {
            if (!rList->list[*iter].hit) {
                ++unused_count;
            }
        }

        rec_file << cached_rules.size() << "\t" << buck_count << "\t" << cached_rules.size() + buck_count<<endl;
        cout << "Stat Cached: " << cached_rules.size() << " rules (" << unused_count << " unused) " << buck_count << " buckets ";

        current[counter] = after[counter]; // evolve traffic
        root->clearHitFlag();
        rList->clearHitFlag();
    }

}

void bucket_tree::print_tree(const string & filename, bool det) { // const
    ofstream out(filename);
    print_bucket(out, root, det);
    out.close();
}

