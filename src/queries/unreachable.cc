#include "src/query.h"
#include "src/vulns.h"
using namespace wasmati;

void VulnerabilityChecker::UnreachableCode() {
    std::set<std::string> targetFuncs;
    if (config.contains(TAINTED) && config.at(TAINTED).is_object()) {
        for (auto const& kv : config.at(TAINTED).items()) {
            targetFuncs.insert(kv.key());
        }
    }
    if (config.contains(SOURCES) && config.at(SOURCES).is_array()) {
        std::set<std::string> sources = config.at(SOURCES);
        targetFuncs.insert(sources.begin(), sources.end());
    }
    if (config.contains(SINKS) && config.at(SINKS).is_array()) {
        std::set<std::string> sinks = config.at(SINKS);
        targetFuncs.insert(sinks.begin(), sinks.end());
    }

    Index counter = 0;
    NodeStream(Query::functions()).forEach([&](Node* func) {
        debug("[DEBUG][Query::UnreachableCode][%u/%u] Function %s\n", counter++,
              numFuncs, func->name().c_str());
        if (func->isImport()) {
            return;
        }
        if (!func->isExport() && targetFuncs.count(func->name()) == 0) {
            return;
        }

        auto pred = Predicate()
                        .instType(InstType::Unreachable)
                        .Or()
                        .instType(InstType::Return, false)
                        .instType(InstType::Block, false)
                        .instType(InstType::Loop, false)
                        .instType(InstType::Unreachable, false)
                        .inEdge(EdgeType::CFG, false);
        auto queryInsts = Query::instructions({func}, pred);
        if (!queryInsts.empty()) {
            vulns.emplace_back(VulnType::Unreachable, func->name(), "", "");
        }
    });
}
