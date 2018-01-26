#include "headers.h"
#include "TraceAnalyze.h"

int main() {
    string rulefile = "../para_src/rule4000";
    rule_list rList(rulefile, true);
    rList.print("../para_src/rList.dat");

    syn_trace_measure(rList, "./Trace_Generate/trace-20k-0.01-10/GENtrace/ref_trace.gz", "./Trace_Generate/trace-20k-0.01-10/GENtrace/ref_trace.txt");
}
