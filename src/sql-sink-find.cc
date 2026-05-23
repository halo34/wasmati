#include "graph.h"
#include "query.h"
#include "vulns.h"

using namespace wasmati;

std::string SQLSinkFind(wasmati::Node* func) {
    std::set<std::string> sinks = defaultConfig[SINKS];
    auto sinkCode =
        NodeStream(func)
            .instructions(Predicate()
                              .instType(InstType::Call)
                              .TEST(sinks.count(node->label()) == 1))
            .findFirst();

    if (sinkCode.isPresent()) {
        return " sql sink exist " + sinkCode.get()->label();
    } else {
        return " no sql sink";
    }
}