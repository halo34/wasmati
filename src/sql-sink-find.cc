
#include "graph.h"
#include "query.h"
#include "vulns.h"

using namespace wasmati;

Node* findConstNode(Node* node, int depth = 0) {
    int limit = 6;
    if (node == nullptr || depth >= limit) {
        return nullptr;
    }
    for (auto e : node->outEdges(EdgeType::CFG)) {
        auto child = e->dest();
        if (!child)
            continue;
        if (child->instType() == InstType::Const) {
            return child;
        }
        if (auto res = findConstNode(child, depth + 1)) {
            return res;
        }
    }
    return nullptr;
}

std::string SQLSinkFind(wasmati::Node* func, wasmati::Node* call) {
    std::set<std::string> sinks = defaultConfig[SINKS];
    auto sinkCode =
        NodeStream(func)
            .instructions(Predicate()
                              .instType(InstType::Call)
                              .TEST(sinks.count(node->label()) == 1))
            .findFirst();
    



    if (sinkCode.isPresent()) {
            
        Node* callConstNode = findConstNode(call);
        Node* sinkConstNode = findConstNode(sinkCode.get());
        
        std::string diff = "no attack suggest found";
        if (callConstNode != nullptr && sinkConstNode != nullptr) {
            diff ="attack: A*" +std::to_string(sinkConstNode->value().u32 -
                                  callConstNode->value().u32) + "<cmd>" ;
        }

 
        

        return " sql sink exist " + sinkCode.get()->label() + " " + diff;

    }
    else {
        return " no sql sink";
    }
}

