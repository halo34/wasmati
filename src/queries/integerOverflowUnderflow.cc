#include "src/query.h"
#include "src/vulns.h"
using namespace wasmati;

void VulnerabilityChecker::IntegerOverflowUnderflow() {
    auto start = std::chrono::high_resolution_clock::now();
    std::set<std::string> ignore = config[IGNORE];

    std::set<std::string> memorySinks{};

    if (config.contains(BUFFER_OVERFLOW) && config.at(BUFFER_OVERFLOW).is_object()) {
        for (auto const& kv : config.at(BUFFER_OVERFLOW).items()) {
            memorySinks.insert(kv.key());
        }
    }
    if (config.contains(BO_MEMCPY) && config.at(BO_MEMCPY).is_array()) {
        std::set<std::string> memcopyLike = config.at(BO_MEMCPY);
        memorySinks.insert(memcopyLike.begin(), memcopyLike.end());
          
    }
    if (config.contains(MALLOC) && config.at(MALLOC).is_array()) {
        std::set<std::string> mallocLike = config.at(MALLOC);
        memorySinks.insert(mallocLike.begin(), mallocLike.end());
    }

    std::set<std::string> seen{};

    for (auto func: Query::functions())
    {
        if (ignore.count(func->name()) ==1) {
            continue;
        }
        const bool explicitTaintRoot = config.contains(TAINTED) && config.at(TAINTED).is_object() &&
            config.at(TAINTED).contains(func->name());
        bool functionMarkedTaint {false};
        std::string functionParameterTaint {};
        std::string functionSourceTaint{};
        NodeStream(func).parameters().forEach([&](Node* node) {
           std::set<std::string> visited{}; 
           auto tained = isTainted(node, visited);
           if (tained.first.empty()) {
            return;
           }
           functionMarkedTaint = true;
           if (functionParameterTaint.empty()){
            functionParameterTaint = tained.first;
            functionSourceTaint = tained.second;
           }
        });

        auto arithmeticPredicate = Predicate().instType(InstType::Binary)
            .insert(
                Predicate()
                    .opcode(Opcode::I32Add)
                    .Or()
                    .opcode(Opcode::I32Sub)
                    .Or()
                    .opcode(Opcode::I32Mul)
                    .Or()
                    .opcode(Opcode::I64Add)
                    .Or()
                    .opcode(Opcode::I64Sub)
                    .Or()
                    .opcode(Opcode::I64Mul)
            );
        NodeStream(func).instructions(arithmeticPredicate).forEach([&](Node* arthOpt){
            std::string taintParam {};
            std::string taintSourceFunction{};
            
            auto arithmeticLocals = EdgeStream(arthOpt->inEdges(EdgeType::PDG))
                .setUnion(arthOpt->outEdges(EdgeType::PDG))
                .filterPDG(PDGType::Local)
                .distincLabel()
                .map<std::string>([](Edge* e){ return e->label(); });
            
           for (const auto& local : arithmeticLocals) {
                auto param = NodeStream(func)
                                 .parameters(Predicate().name(local))
                                 .findFirst();
                if (!param.isPresent()) {
                    continue;
                }
                std::set<std::string> visited{};
                auto tainted = isTainted(param.get(), visited);
                if (!tainted.first.empty()) {
                    taintParam = tainted.first;
                    taintSourceFunction = tainted.second;
                    break;
                }
            }
            if (taintParam.empty()) {
                NodeStream(func).parameters().forEach([&](Node* parameter) {
                    if (!taintParam.empty()) {
                        return;
                    }
                    std::set<std::string> visited{};
                    auto tainted = isTainted(parameter, visited);
                    if (tainted.first.empty()) {
                        return;
                    }
                    auto dependencies = Query::BFS({parameter}, Query::TRUE_PREDICATE, Query::PDG_EDGES);
                    if (dependencies.count(arthOpt) == 0) {
                        return;
                    }
                    taintParam = tainted.first;
                    taintSourceFunction = tainted.second;
                });
            }
            if (taintParam.empty()) {
                if (!functionMarkedTaint || !explicitTaintRoot) {
                    return;
                }
                taintParam = functionParameterTaint;
                taintSourceFunction = functionSourceTaint;
            }
            auto sinkPredicateTest = Predicate().TEST(
                (node->instType() == InstType::Call &&
                 memorySinks.count(node->label()) == 1) ||
                node->instType() == InstType::Store ||
                node->instType() == InstType::Load);
            
            NodeStream(arthOpt).BFS(sinkPredicateTest, Query::PDG_EDGES, 12)
                .forEach([&](Node* potentialMemorySink) {
                    auto sinkLocals = EdgeStream(potentialMemorySink->inEdges(EdgeType::PDG))
                        .setUnion(potentialMemorySink->outEdges(EdgeType::PDG))
                        .filterPDG(PDGType::Local)
                        .distincLabel()
                        .map<std::string>([](Edge* e){ return e->label(); });

                    bool sharesLocalFlow{false};
                    for (const auto& arithmeticLocal : arithmeticLocals) {
                        if (std::find(sinkLocals.begin(), sinkLocals.end(), arithmeticLocal) != sinkLocals.end()) {
                            sharesLocalFlow = true;
                            break;
                        }
                    }
                    if (!sharesLocalFlow) {
                        return;
                    }

                    const std::string sinkType = potentialMemorySink->instType() == InstType::Call ? potentialMemorySink->label() : INST_TYPE_MAP.at(potentialMemorySink->instType());
                    const std::string arthType = !arthOpt->label().empty() ? arthOpt->label() : std::string{arthOpt->opcode().GetName()};
                    const std::string key{func->name() + ":" + taintParam + ":" + arthType + ":" + sinkType};
                    if (seen.count(key) == 1) {
                        return;
                    }
                    seen.insert(key);
                    std::string sinkContext{};
                    if (potentialMemorySink->instType() == InstType::Load) {
                        sinkContext = "index/pointer arithmetic reaches memory read (Load)";
                    } else if (potentialMemorySink->instType() == InstType::Store) {
                        sinkContext = "index/pointer arithmetic reaches memory write (Store)";
                    } else {
                        sinkContext = "arithmetic value reaches memory-sensitive call sink " + sinkType;
                    }
                    std::stringstream description{};
                    description << "Integer overflow candidate in function " << taintSourceFunction
                                << ": tainted parameter " << taintParam
                                << " reaches arithmetic operation " << arthType
                                << " and " << sinkContext;
                    vulns.emplace_back(VulnType::IntegerOverflowUnderflow, func->name(), potentialMemorySink->label(), description.str());
                });
            });
        
    }

}
