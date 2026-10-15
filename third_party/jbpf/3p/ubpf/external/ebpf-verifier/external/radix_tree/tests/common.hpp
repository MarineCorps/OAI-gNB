#pragma once

#include <algorithm>
#include <map>
#include <random>

#include <gtest/gtest.h>
#include <radix_tree.hpp>

// this file contains some common code for all tests to reduce the number of copypaste lines

using tree_t = radix_tree<std::string, int>;
using vector_found_t = std::vector<tree_t::iterator>;
using map_found_t = std::map<std::string, int>;

inline std::vector<std::string> get_unique_keys() {
    std::vector<std::string> vec{"a",   "b",   "ab",  "ba",  "aa",  "bb",  "aaa",
                                 "aab", "aba", "baa", "bba", "bab", "abb", "bbb"};
    std::ranges::sort(vec);
    EXPECT_TRUE(std::ranges::adjacent_find(vec) == vec.end());
    return vec;
}

inline map_found_t vec_found_to_map(const vector_found_t& vec) {
    map_found_t result;
    for (const auto& it : vec) {
        result.emplace(it->first, it->second);
    }
    return result;
}
