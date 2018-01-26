#ifndef __TRACE_ANALYZE_H
#define __TRACE_ANALYZE_H

#include "headers.h"
#include "Address.hpp"
#include <set>
#include <boost/unordered_set.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/filesystem.hpp>
#include "RuleList.h"

using std::string;

void syn_trace_plot_hp(string, string);

void syn_trace_measure(rule_list &, string, string);

#endif
