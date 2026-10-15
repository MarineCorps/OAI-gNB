#include "common.hpp"

TEST(find, nothing_in_empty) {
    std::vector<std::string> unique_keys = get_unique_keys();
    tree_t tree;
    for (const auto& key : unique_keys) {
        auto it = tree.find(key);
        ASSERT_EQ(tree.end(), it);
    }
}

TEST(find, find_after_insert_or_erase) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    for (size_t i = 0; i < unique_keys.size(); i++) {
        tree_t tree;
        std::map<std::string, int> value_map;
        { // fill tree with some data and save values in map
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                int value = randeng() % 100;
                tree.insert(tree_t::value_type(key, value));
                value_map[key] = value;
            }
        }
        {
            SCOPED_TRACE("try to find existent key");
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                auto it = tree.find(key);
                ASSERT_NE(tree.end(), it);
                ASSERT_EQ(value_map[it->first], it->second);
            }
        }
        {
            SCOPED_TRACE("find should fail to find removed key");
            for (const auto& key : unique_keys) {
                tree.erase(key);
                auto it = tree.find(key);
                ASSERT_EQ(tree.end(), it);
            }
        }
    }
}
