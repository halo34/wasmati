#ifndef SQL_SINK_FIND_H_
#define SQL_SINK_FIND_H_

#include "graph.h"
#include "query.h"
#include "vulns.h"

std::string CmdSinkFind(wasmati::Node* func, wasmati::Node* call);

#endif