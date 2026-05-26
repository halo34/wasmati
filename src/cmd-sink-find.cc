
#include "graph.h"
#include "query.h"
#include "vulns.h"

using namespace wasmati;

Node* findConstNode(Node* call_child) {
    Node* addNode = nullptr;
    if (call_child->instType() == InstType::Binary) {
        if (strcmp(call_child->opcode().GetName(), "i32.add") == 0) {
            addNode = call_child;
        }
    }
    
    else if (call_child->instType() == InstType::LocalGet) {
        auto findBinPred =
            Predicate()
                .type(NodeType::Instruction)
                .instType(InstType::Binary)
                .TEST(strcmp(node->opcode().GetName(), "i32.add") == 0)
                .EXEC(addNode = node);
        Query::BFS({call_child}, findBinPred, Query::PDG_EDGES, 6, true);
    }
    else {
        return nullptr; // NOT FOUND
    }

    auto addParent = addNode->getParent(1, EdgeType::PDG);
    if (addParent->instType()==InstType::Const){
        return addParent; // found
    }
    else{
        auto constPred = Predicate().type(NodeType::Instruction).instType(InstType::Const);

        auto vals = Query::BFS({addNode->getParent(1, EdgeType::PDG)}, constPred,
                           Query::PDG_EDGES, 6, true);

    for (auto val : vals) {
        return val;  // get first one
    }
    return nullptr;
    }
}

std::string CmdSinkFind(wasmati::Node* func, wasmati::Node* call) {

    auto sinkCode =
        NodeStream(func)
            .instructions(
                Predicate()
                    .instType(InstType::Call)
                    .TEST(defaultConfig[CMD_SINKS].contains(node->label())))
            .findFirst();

    if (sinkCode.isPresent()) {
        Index index = defaultConfig[CMD_SINKS][sinkCode.get()->label()];

        Node* sinkConstNode = findConstNode(sinkCode.get()->getChild(index));
        //
        Node* callConstNode = findConstNode(call);
        std::string diff = "";
        if( callConstNode != nullptr && sinkConstNode != nullptr){
        
        
        
        diff = "attack: A*" +
                std::to_string(sinkConstNode->value().u32 -
                                callConstNode->value().u32) +
                "<cmd>";
        }

        

        return " cmd exec sink exist " + sinkCode.get()->label() + " " + diff;

    }
    else {
        return " no cmd exec sink";
    }
}

