#include "common.hpp"

TEST(insert, change_size) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    for (size_t i = 0; i < unique_keys.size(); i++) {
        tree_t tree;
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (size_t j = 0; j < unique_keys.size(); j++) {
                const std::string& key = unique_keys[j];
                ASSERT_EQ(j, tree.size());
                tree.insert(tree_t::value_type(key, randeng() % 100));
                ASSERT_EQ(j + 1, tree.size());
            }
        }
        { // try to insert with duplicate keys
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                ASSERT_EQ(unique_keys.size(), tree.size());
                tree.insert(tree_t::value_type(key, randeng() % 100));
                ASSERT_EQ(unique_keys.size(), tree.size());
            }
        }
    }
}

TEST(insert, success_if_key_unique) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    for (size_t i = 0; i < unique_keys.size(); i++) {
        tree_t tree;
        std::ranges::shuffle(unique_keys, randeng);
        for (const auto& key : unique_keys) {
            std::pair<tree_t::iterator, bool> r = tree.insert(tree_t::value_type(key, randeng() % 100));
            ASSERT_TRUE(r.second) << "fail to insert key=" << key;
        }
    }
}

TEST(insert, fail_if_key_duplicate) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    for (size_t i = 0; i < unique_keys.size(); i++) {
        tree_t tree;
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }
        { // try to insert with duplicate keys
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                std::pair<tree_t::iterator, bool> r = tree.insert(tree_t::value_type(key, randeng() % 100));
                ASSERT_FALSE(r.second) << "unexpectedly inserted key=" << key;
            }
        }
    }
}

TEST(insert, dont_replace_prev_value) {
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
        { // try to overwrite by key
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }
        { // check old data was not modified
            ASSERT_EQ(value_map.size(), tree.size());
            for (auto it = tree.begin(); it != tree.end(); ++it) {
                ASSERT_FALSE(!value_map.contains(it->first)) << "there is no such key in map";
                ASSERT_EQ(value_map[it->first], it->second);
            }
        }
    }
}

TEST(insert, operator_index_call_default_ctor) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    std::ranges::shuffle(unique_keys, randeng);
    tree_t tree;
    for (const auto& unique_key : unique_keys) {
        ASSERT_EQ(0, tree[unique_key]);
    }
}

TEST(insert, after_erase) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    std::ranges::shuffle(unique_keys, randeng);
    tree_t tree;
    for (const auto& key : unique_keys) {
        tree.insert(tree_t::value_type(key, randeng() % 100));
        tree.erase(key);
        auto [fst, snd] = tree.insert(tree_t::value_type(key, randeng() % 100));
        ASSERT_TRUE(snd);
    }
}
