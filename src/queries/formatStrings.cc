#include "src/query.h"
#include "src/vulns.h"
using namespace wasmati;

void VulnerabilityChecker::FormatStrings() {
    auto start = std::chrono::high_resolution_clock::now();
    json fsConfig = config.at(FORMAT_STRING);
    std::set<std::string> ignore = config[IGNORE];

    auto altLabel = [](const std::string& label) {
        if (!label.empty() && label[0] == '$') {
            return label.substr(1);
        }
        return std::string("$") + label;
    };

    Index counter = 0;
    for (auto func : Query::functions()) {
        debug("[DEBUG][Query::FormatString][%u/%u] Function %s\n", counter++,
              numFuncs, func->name().c_str());
        if (ignore.count(func->name()) || fsConfig.contains(func->name())) {
            continue;
        }

        Node* child = nullptr;
        auto callPredicate =
            Predicate()
                .instType(InstType::Call)
                .TEST(fsConfig.contains(node->label()) ||
                      fsConfig.contains(altLabel(node->label())))
                .EXEC(child = node->getChild(fsConfig.contains(node->label())
                                                 ? fsConfig.at(node->label())
                                                 : fsConfig.at(
                                                       altLabel(node->label()))))
                .PDG_EDGE(child, node, PDGType::Const, false);

        NodeStream(func).instructions(callPredicate).forEach([&](Node* call) {
            // write vulns
            vulns.emplace_back(VulnType::FormatStrings, func->name(),
                               call->label());
        });
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    info["formatStrings"] = time;
}
