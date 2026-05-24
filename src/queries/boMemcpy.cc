#include "src/query.h"
#include "src/vulns.h"
#include "src/cmd-sink-find.h"
using namespace wasmati;

void VulnerabilityChecker::BOMemcpy() {
    auto start = std::chrono::high_resolution_clock::now();
    std::set<std::string> memcpyFuncs = config.at(BO_MEMCPY);
    std::set<std::string> ignore = config[IGNORE];

    std::set<std::string> sinks = config[SINKS];
    for (auto func : Query::functions()) {
  
       
                

        if (ignore.count(func->name()) == 1) {
            continue;
        }

        if (memcpyFuncs.count(func->name()) == 1) {
            // if it is already a sink, no use check
            continue;
        }

        NodeStream(func)
            .instructions(Predicate()
                              .instType(InstType::Call)
                              .TEST(memcpyFuncs.count(node->label()) == 1))
            .forEach([&](Node* call) {
                auto dest = call->getChild(0);
                bool isDestStatic =
                    NodeStream(dest)
                        .filter(Predicate()
                                    .inPDGEdge("$g0", PDGType::Global)
                                    .Or()
                                    .outPDGEdge(PDGType::Const))
                        .findFirst()
                        .isPresent() ||
                    (dest->instType() == InstType::Load &&
                     dest->outEdges(EdgeType::AST).size() == 1 &&
                     Query::containsEdge(dest->inEdges(EdgeType::PDG),
                                         [](Edge* e) {
                                             return e->pdgType() ==
                                                    PDGType::Const;
                                         })) ||
                    verifyMallocConst(dest).first;

                if (!isDestStatic) {
                    return;
                }

                auto src = call->getChild(1);
                auto parameters = Query::parameters({func});
                auto localVarDeps =
                    EdgeStream(src->outEdges(EdgeType::PDG))
                        .setUnion(src->inEdges(EdgeType::PDG))
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
                    desc << localVar->name() << " tainted from param"
                         << tainted.first << " in " << tainted.second;

                    desc << CmdSinkFind(func,call);
                    vulns.emplace_back(VulnType::BufferOverflow, func->name(),
                                       call->label(), desc.str());
                                       
                    break;
                }

                // Fallback for modern compiler lowering:
                // if direct local-name matching misses, try PDG reachability
                // from function parameters to source operand.
                bool reported = false;
                for (auto param : parameters) {
                    std::set<std::string> visited;
                    auto tainted = isTainted(param, visited);
                    if (tainted.first == "") {
                        continue;
                    }
                    auto deps =
                        Query::BFS({param}, Query::TRUE_PREDICATE,
                                   Query::PDG_EDGES);
                    if (deps.count(src) == 0) {
                        continue;
                    }
                    std::stringstream desc;
                    desc << param->name() << " tainted from param"
                         << tainted.first << " in " << tainted.second;

                    desc << CmdSinkFind(func,call);

                    vulns.emplace_back(VulnType::BufferOverflow, func->name(),
                                       call->label(), desc.str());
                    reported = true;

                   
                    break;
                }
                if (reported) {
                    return;
                }

                // Last-resort fallback:
                // if this function has tainted parameters at all, and the
                // sink is a memcpy-like call into a static destination, treat
                // it as potentially overflowing.

                // THIS IS THE ONE THAT THE code returns
                for (auto param : parameters) {
                    std::set<std::string> visited;
                    auto tainted = isTainted(param, visited);
                    if (tainted.first == "") {
                        continue;
                    }
                    std::stringstream desc;
                    desc << param->name() << " tainted from param"
                         << tainted.first << " in " << tainted.second;

                    desc << CmdSinkFind(func,call);

                    

                   
                    

                         //for (auto e : call->outEdges(EdgeType::CFG)) {
                         //auto child = e->dest();
                         //desc << " CHILD NODE"
                         //        << INST_TYPE_MAP.at(child->instType()) <<
                         //        "\n";
                         //
                         //for (auto f : child->outEdges(EdgeType::CFG)) {
                         //    auto nchild = f->dest();
                         //    desc << " CHILD child NODE" << EDGE_TYPES_MAP.at(f->type())
                         //         << INST_TYPE_MAP.at(nchild->instType())
                         //         << "\n";
                         //}
                         //}
                        

                        vulns.emplace_back(VulnType::BufferOverflow,
                                           func->name(), call->label(),
                                           desc.str());
                    break;
                }
            });
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    info["boMemcpy"] = time;
}
