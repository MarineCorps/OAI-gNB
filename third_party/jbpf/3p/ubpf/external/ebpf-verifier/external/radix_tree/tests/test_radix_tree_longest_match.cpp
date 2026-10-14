#include "common.hpp"

TEST(longest_match, empty_tree) {
    const std::vector<std::string> unique_keys = get_unique_keys();
    tree_t tree;
    for (const auto& key : unique_keys) {
        auto found_it = tree.longest_match(key);
        ASSERT_EQ(found_it, tree.end());
    }
}

TEST(longest_match, complex_tree) {
    tree_t tree;

    tree["abcdef"] = 1;
    tree["abcdege"] = 2;
    tree["bcdef"] = 3;
    tree["cd"] = 4;
    tree["ce"] = 5;
    tree["c"] = 6;

    {
        SCOPED_TRACE("longest_match should find object by existent key");
        for (auto it = tree.begin(); it != tree.end(); ++it) {
            auto found_it = tree.longest_match(it->first);
            ASSERT_NE(found_it, tree.end());
            ASSERT_EQ(tree[it->first], found_it->second);
        }
    }
    {
        SCOPED_TRACE("longest_match should find nothing by empty key");
        const auto found_it = tree.longest_match("");
        ASSERT_EQ(found_it, tree.end());
    }
    {
        SCOPED_TRACE("longest_match corrects typos in suffix");
        std::map<std::string, std::string> typos{
            {"abcdefe", "abcdef"}, {"abcdegeasdf", "abcdege"},
            {"bcdefege", "bcdef"}, {"ced", "ce"},
            {"cdef", "cd"},        {"cf", "c"},
            {"ca", "c"},           {"ccdef", "c"},
        };
        for (const auto& [fst, snd] : typos) {
            SCOPED_TRACE(fst);
            auto found_it = tree.longest_match(fst);
            ASSERT_NE(found_it, tree.end());
            ASSERT_EQ(snd, found_it->first);
            ASSERT_EQ(tree[snd], found_it->second);
        }
    }
    {
        SCOPED_TRACE("should never be found");
        const std::vector<std::string> should_never_be_found{"a",     "b",      "d",   "e",   "f",
                                                             "abcde", "bcdege", "acd", "bce", "acdef"};
        for (const auto& key : should_never_be_found) {
            SCOPED_TRACE(key);
            auto found_it = tree.longest_match(key);
            ASSERT_EQ(found_it, tree.end());
        }
    }
}
