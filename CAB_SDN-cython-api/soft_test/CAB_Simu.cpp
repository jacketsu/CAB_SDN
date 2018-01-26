#include "Rule.hpp"
#include "RuleList.h"
#include "BucketTree.h"
#include "OFswitch.h"
#include <getopt.h>

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

using std::cout;
using std::endl;
using std::ofstream;

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace fs = boost::filesystem;

void logging_init() {
    fs::create_directory("./log");
    logging::add_file_log
    (
        keywords::file_name = "./log/sample_%N.log",
        keywords::rotation_size = 10 * 1024 * 1024,
        keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
        keywords::format = "[%TimeStamp%]: %Message%"
    );
}

void print_usage() {
    std::cerr << "Usage: ./CAB_Simu (--config <config_file>)" << endl 
              << "Example: ./CAB_Simu -c ../config/CABSimu_config.ini" << endl 
              << "Options: " << endl
              << " -b, --batch              batch test" << endl 
              << " -p, --preload            specify # of preloaded rule" << endl
              << " -r, --rule               specify rule list file" << endl
              << " -t, --thres              specify bucket tree hard threshold" << endl
              << " -i, --input              specify trace directory" << endl;
}

int main(int argc, char* argv[]) {
    int getopt_res;
    string para_file;
    int preload_capacity = 400;
    int thres_hard = 8;
    string rule_file;
    string input;
    bool batch_proc = false;

    while (1) {
        static struct option cab_simu_options[] = {
            {"batch",       no_argument,                0, 'b'},
            {"help",        no_argument,                0, 'h'},
            {"config",      required_argument,          0, 'c'},
            {"preload",     required_argument,          0, 'p'},
            {"rule",        required_argument,          0, 'r'},
            {"thres",       required_argument,          0, 't'},
            {"input",       required_argument,          0, 'i'},
            {0,             0,                          0,  0}
        };

        int option_index = 0;

        getopt_res = getopt_long (argc, argv, "bhc:p:r:t:i:",
                                  cab_simu_options, &option_index);

        if (getopt_res == -1)
            break;

        switch (getopt_res) {
        case 0:
            if (cab_simu_options[option_index].flag != 0)
                break;
        case 'b':
            batch_proc = true;
            break;
        case 'c':
            para_file = string(optarg);
            break;
        case 'i':
            input = string(optarg);
            break;
        case 't':
            thres_hard = atoi(optarg);
            break;
        case 'p':
            preload_capacity = atoi(optarg);
            break;
        case 'r':
            rule_file = string(optarg);
            break;
        case 'h':
            print_usage();
            return 0;
        case '?':
            print_usage();
            return 0;
        default:
            cout<<getopt_res<<endl;
            abort();
        }
    }

    srand (time(NULL));
    logging_init();
    rule_list rList(rule_file);
    rList.obtain_dep();

    fs::path dir(input);
    bucket_tree bTree(rList, thres_hard, false, preload_capacity);
    bTree.pre_alloc();

    OFswitch ofswitch;
    ofswitch.set_para(para_file, &rList, &bTree);

    vector<fs::path> pvec;
    std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(pvec));
    std::sort(pvec.begin(), pvec.end());

    for (auto it = pvec.begin(); it != pvec.end(); ++it) {
        ofswitch.tracefile_str = it->string() + "/GENtrace/ref_trace.gz";
        // run CAB
        ofswitch.mode = 0;
        ofswitch.run_test();
        // run CMR
        ofswitch.mode = 3;
        ofswitch.run_test();
    }

    return 0;
}
