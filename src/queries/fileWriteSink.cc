// wasmati/src/queries/fileWriteSink.cc
#include "src/query.h"
#include "src/vulns.h"
using namespace wasmati;

void VulnerabilityChecker::FileWriteSink() {
    auto start = std::chrono::high_resolution_clock::now();

    if (!config.contains(FILE_WRITE) || !config.at(FILE_WRITE).is_object()) {
        info["fileWriteSink"] = 0;
        return;
    }

    json fwConfig = config.at(FILE_WRITE);
    std::set<std::string> ignore = config[IGNORE];

    std::set<std::string> fwSinks;
    for (auto const& kv : fwConfig.items()) {
        fwSinks.insert(kv.key());
    }

    Index counter = 0;
    for (auto func : Query::functions()) {
        debug("[DEBUG][Query::FileWriteSink][%u/%u] Function %s\n", counter++,
              numFuncs, func->name().c_str());

        if (ignore.count(func->name()) == 1) {
            continue;
        }

        if (fwSinks.count(func->name()) == 1) {
            // wenn Funktion selbst Sink ist, in dieser Query skippen
            continue;
        }

        NodeStream(func)
            .instructions(Predicate()
                              .instType(InstType::Call)
                              .TEST(fwSinks.count(node->label()) == 1))
            .forEach([&](Node* call) {
                if (!fwConfig.at(call->label()).contains("bufferParam")) {
                    return;
                }

                Index bufferParam = fwConfig.at(call->label()).at("bufferParam");
                Node* arg = call->getChild(bufferParam);

                auto localVarDeps =
                    EdgeStream(arg->outEdges(EdgeType::PDG))
                        .setUnion(arg->inEdges(EdgeType::PDG))
                        .filterPDG(PDGType::Local)
                        .filter([&](Edge* e) {
                            return NodeStream(func)
                                .parameters(Predicate().name(e->label()))
                                .findFirst()
                                .isPresent();
                        })
                        .map<Node*>([&](Edge* e) {
                            return NodeStream(func)
                                .parameters(Predicate().name(e->label()))
                                .findFirst()
                                .get();
                        });

                for (auto const localVar : localVarDeps) {
                    std::set<std::string> visited;
                    auto tainted = isTainted(localVar, visited);
                    if (tainted.first == "") {
                        continue;
                    }

                    std::stringstream desc;
                    desc << "tainted data from param " << tainted.first
                         << " in " << tainted.second
                         << " reaches file-write sink " << call->label()
                         << " (arg " << bufferParam << ")";
                    vulns.emplace_back(VulnType::Tainted, func->name(),
                                       call->label(), desc.str());
                    return;
                }

                // Fallback: PDG-Reachability von tainted Parametern zu arg
                for (auto param : Query::parameters({func})) {
                    std::set<std::string> visited;
                    auto tainted = isTainted(param, visited);
                    if (tainted.first == "") {
                        continue;
                    }

                    auto deps = Query::BFS({param}, Query::TRUE_PREDICATE,
                                           Query::PDG_EDGES);
                    if (deps.count(arg) == 0) {
                        continue;
                    }

                    std::stringstream desc;
                    desc << "tainted data from param " << tainted.first
                         << " in " << tainted.second
                         << " reaches file-write sink " << call->label()
                         << " (arg " << bufferParam << ")";
                    vulns.emplace_back(VulnType::FileWriteSink, func->name(),
                                       call->label(), desc.str());
                    return;
                }
            });
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    info["fileWriteSink"] = time;
}