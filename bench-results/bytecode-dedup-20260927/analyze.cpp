#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

struct Code { uint64_t bytes = 0, references = 0; };
static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
static bool hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static void trim_cr(std::string& line) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
}
int main(int argc, char** argv) try {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    require(argc >= 2, "usage: analyze lengths | analyze references lengths.tsv");
    const std::string mode = argv[1];
    std::string line;
    uint64_t rows = 0;
    if (mode == "lengths") {
        require(bool(std::getline(std::cin, line)), "missing bytecodes header");
        trim_cr(line);
        require(line == "bytecode_hash,bytecode", "unexpected bytecodes header");
        uint64_t bytes = 0;
        while (std::getline(std::cin, line)) {
            trim_cr(line);
            const size_t comma = line.find(',');
            require(comma != std::string::npos, "missing bytecode comma");
            const std::string key = line.substr(0, comma);
            require(key.size() == 66 && key.substr(0, 2) == "0x", "invalid hash width");
            require(std::all_of(key.begin() + 2, key.end(), hex), "invalid hash");
            size_t start = comma + 1;
            if (start != line.size()) {
                require(line.compare(start, 2, "\\x") == 0, "invalid bytecode prefix");
                start += 2;
            }
            require((line.size() - start) % 2 == 0, "odd bytecode hex length");
            require(std::all_of(line.begin() + start, line.end(), hex), "invalid code hex");
            const uint64_t length = (line.size() - start) / 2;
            std::cout << key << '\t' << length << '\n';
            bytes += length;
            if (++rows % 100000 == 0) std::cerr << "bytecodes=" << rows << " bytes=" << bytes << '\n';
        }
        require(std::cin.eof(), "bytecode input failed");
        std::cerr << "bytecodes=" << rows << " bytes=" << bytes << " done\n";
        return 0;
    }
    require(mode == "references" && argc == 3, "invalid arguments");
    std::unordered_map<std::string, Code> codes;
    codes.reserve(2000000);
    std::ifstream sizes(argv[2]);
    require(bool(sizes), "cannot open lengths file");
    std::string key;
    uint64_t length;
    while (sizes >> key >> length)
        require(codes.emplace(key, Code{length, 0}).second, "duplicate hash in lengths");
    require(sizes.eof(), "invalid lengths file");
    require(bool(std::getline(std::cin, line)), "missing contracts header");
    trim_cr(line);
    require(line == "address,bytecode_hash,blocknum", "unexpected contracts header");
    uint64_t empty = 0, missing_hash = 0, missing_block = 0, max_block = 0, min_block = UINT64_MAX;
    while (std::getline(std::cin, line)) {
        trim_cr(line);
        const size_t a = line.find(','), b = line.find(',', a + 1);
        require(a == 42 && b != std::string::npos, "invalid contract row");
        const std::string hash = line.substr(a + 1, b - a - 1);
        if (hash.empty()) {
            ++missing_hash;
        } else {
            auto it = codes.find(hash);
            if (it == codes.end()) throw std::runtime_error("contract references missing code hash: " + line);
            ++it->second.references;
            empty += it->second.bytes == 0;
        }
        const auto block_text = line.substr(b + 1);
        if (block_text.empty()) {
            ++missing_block;
        } else {
            if (!std::all_of(block_text.begin(), block_text.end(), [](char c) { return c >= '0' && c <= '9'; }))
                throw std::runtime_error("invalid deployment block: " + line);
            const auto block = std::stoull(block_text);
            min_block = std::min<uint64_t>(min_block, block);
            max_block = std::max<uint64_t>(max_block, block);
        }
        if (++rows % 5000000 == 0) std::cerr << "contracts=" << rows << '\n';
    }
    require(std::cin.eof(), "contract input failed");
    uint64_t all_bytes = 0, unique_bytes = 0, repeated_bytes = 0;
    uint64_t used_hashes = 0, shared_hashes = 0, shared_contracts = 0, single_bytes = 0;
    std::array<uint64_t, 6> bin_unique{}, bin_repeated{}, bin_refs{};
    std::vector<std::pair<std::string, Code>> top;
    for (const auto& [hash, code] : codes) {
        all_bytes += code.bytes;
        if (code.references == 0) continue;
        ++used_hashes;
        unique_bytes += code.bytes;
        repeated_bytes += code.bytes * code.references;
        if (code.references > 1) {
            ++shared_hashes;
            shared_contracts += code.references;
        } else single_bytes += code.bytes;
        size_t bin = code.bytes < 1024 ? 0 : code.bytes < 5120 ? 1 : code.bytes < 10240 ? 2
                   : code.bytes < 20480 ? 3 : code.bytes <= 24576 ? 4 : 5;
        bin_unique[bin] += code.bytes;
        bin_repeated[bin] += code.bytes * code.references;
        bin_refs[bin] += code.references;
        top.emplace_back(hash, code);
    }
    std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
        return a.second.bytes * (a.second.references - 1) > b.second.bytes * (b.second.references - 1);
    });
    std::cout << std::setprecision(12)
      << "{\n  \"scope\": \"Zellic historical deployments, not current live state\",\n"
      << "  \"contract_rows\": " << rows << ",\n"
      << "  \"empty_code_contract_rows\": " << empty << ",\n"
      << "  \"missing_code_hash_rows\": " << missing_hash << ",\n"
      << "  \"accounted_contract_rows\": " << rows - missing_hash << ",\n"
      << "  \"missing_deployment_block_rows\": " << missing_block << ",\n"
      << "  \"minimum_deployment_block\": " << min_block << ",\n"
      << "  \"maximum_deployment_block\": " << max_block << ",\n"
      << "  \"all_code_hashes\": " << codes.size() << ",\n"
      << "  \"referenced_code_hashes\": " << used_hashes << ",\n"
      << "  \"shared_code_hashes\": " << shared_hashes << ",\n"
      << "  \"contract_rows_with_shared_code\": " << shared_contracts << ",\n"
      << "  \"all_unique_code_bytes\": " << all_bytes << ",\n"
      << "  \"deduplicated_referenced_bytes\": " << unique_bytes << ",\n"
      << "  \"without_deduplication_bytes\": " << repeated_bytes << ",\n"
      << "  \"saved_bytes\": " << repeated_bytes - unique_bytes << ",\n"
      << "  \"expansion_factor\": " << double(repeated_bytes) / unique_bytes << ",\n"
      << "  \"saved_percent\": " << 100.0 * (repeated_bytes - unique_bytes) / repeated_bytes << ",\n"
      << "  \"single_reference_code_bytes\": " << single_bytes << ",\n"
      << "  \"size_bins\": [\n";
    const char* labels[] = {"under_1KiB", "1_to_5KiB", "5_to_10KiB", "10_to_20KiB", "20_to_24KiB", "above_24KiB"};
    for (size_t i = 0; i < 6; ++i)
        std::cout << "    {\"range\":\"" << labels[i] << "\",\"references\":" << bin_refs[i]
                  << ",\"deduplicated_bytes\":" << bin_unique[i]
                  << ",\"without_deduplication_bytes\":" << bin_repeated[i] << "}" << (i == 5 ? "\n" : ",\n");
    std::cout << "  ],\n  \"top_savings\": [\n";
    const size_t n = std::min<size_t>(20, top.size());
    for (size_t i = 0; i < n; ++i)
        std::cout << "    {\"hash\":\"" << top[i].first << "\",\"bytes\":" << top[i].second.bytes
                  << ",\"references\":" << top[i].second.references << ",\"saved_bytes\":"
                  << top[i].second.bytes * (top[i].second.references - 1) << "}"
                  << (i + 1 == n ? "\n" : ",\n");
    std::cout << "  ]\n}\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
