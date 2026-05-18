#include "src/query.h"
#include "src/vulns.h"
#include <set>
#include <utility>
#include <vector>
using namespace wasmati;

void VulnerabilityChecker::UseAfterFree() {
    auto start = std::chrono::high_resolution_clock::now();
    std::set<std::string> ignore = config[IGNORE];

    Index counter = 0;
    for (auto func : Query::functions()) {
        debug("[DEBUG][Query::UseAfterFree][%u/%u] Function %s\n", counter++,
              numFuncs, func->name().c_str());
        if (ignore.count(func->name())) {
            continue;
        }
        std::set<std::string> seenPairs;
        std::set<std::string> reported;

        for (auto const& item : config[CONTROL_FLOW]) {
            std::string source = item[SOURCE];
            std::string dest = item[DEST];

            std::vector<std::pair<std::string, std::string>> flowPairs = {
                {source, dest}};
            if (source == "$malloc" && dest == "$free") {
                flowPairs.emplace_back("$dlmalloc", "$dlfree");
                flowPairs.emplace_back("$emscripten_builtin_malloc",
                                       "$emscripten_builtin_free");
            }
            if (source == "$dlmalloc" && dest == "$dlfree") {
                flowPairs.emplace_back("$malloc", "$free");
                flowPairs.emplace_back("$emscripten_builtin_malloc",
                                       "$emscripten_builtin_free");
            }

            for (const auto& flow : flowPairs) {
                source = flow.first;
                dest = flow.second;
                auto pairKey = source + "->" + dest;
                if (seenPairs.count(pairKey) == 1) {
                    continue;
                }
                seenPairs.insert(pairKey);

                auto sourcePredicate =
                    Predicate().instType(InstType::Call).label(source);

                auto callSourceInsts =
                    Query::instructions({func}, sourcePredicate);

                for (Node* callSource : callSourceInsts) {
                    auto pdgEdgeCond =
                        Query::pdgEdge(callSource->label(), PDGType::Function);

                    Node* destNode = nullptr;
                    auto destPredicate =
                        Predicate()
                            .type(NodeType::Instruction)
                            .instType(InstType::Call)
                            .label(dest)
                            .EXEC(destNode = node)
                            .reaches(callSource, destNode, pdgEdgeCond);

                    auto destInsts =
                        Query::BFS({callSource}, destPredicate, Query::CFG_EDGES);
                    for (Node* callDest : destInsts) {
                        Node* inst = nullptr;
                        auto uafPredicate =
                            Predicate()
                                .inPDGEdge(callSource->label(),
                                           PDGType::Function)
                                .EXEC(inst = node)
                                .reaches(callSource, inst, pdgEdgeCond);
                        Node* parent = nullptr;
                        auto uafInst =
                            NodeStream(callDest)
                                .BFS(uafPredicate, Query::CFG_EDGES, 1)
                                .filterOut(Predicate()
                                               .instType(InstType::Call)
                                               .label(dest)
                                               .Or()
                                               .EXEC(parent = node->getParent(0))
                                               .TEST(parent->instType() ==
                                                         InstType::Call &&
                                                     parent->label() == dest))
                                .findFirst();

                        if (uafInst.isPresent()) {
                            auto reportKey = func->name() + "|" +
                                             callSource->label() + "|" + dest +
                                             "|" + uafInst.get()->label();
                            if (reported.count(reportKey) == 1) {
                                continue;
                            }
                            reported.insert(reportKey);
                            std::stringstream desc;
                            desc << "Value from call " << callSource->label()
                                 << " used after call to " << dest;
                            vulns.emplace_back(VulnType::UaF, func->name(),
                                               uafInst.get()->label(),
                                               desc.str());
                        }
                    }
                }
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    info["useAfterFree"] = time;
}
