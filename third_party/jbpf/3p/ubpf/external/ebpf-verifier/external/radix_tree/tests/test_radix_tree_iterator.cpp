#include "common.hpp"

TEST(iterator, begin_end) {
    auto randeng = std::default_random_engine();
    {
        SCOPED_TRACE("empty tree");
        tree_t tree;
        ASSERT_EQ(tree.begin(), tree.end());
    }
    {
        SCOPED_TRACE("non empty tree");
        tree_t tree;
        {
            std::vector<std::string> unique_keys = get_unique_keys();
            // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }
        ASSERT_NE(tree.begin(), tree.end());
    }
}

TEST(iterator, distance) {
    auto randeng = std::default_random_engine();
    {
        SCOPED_TRACE("empty tree");
        tree_t tree;
        auto d = std::distance<tree_t::iterator>(tree.begin(), tree.end());
        ASSERT_EQ(0, d);
    }
    {
        SCOPED_TRACE("non empty tree");
        tree_t tree;
        std::vector<std::string> unique_keys = get_unique_keys();
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }
        auto d = std::distance<tree_t::iterator>(tree.begin(), tree.end());
        ASSERT_EQ(unique_keys.size(), static_cast<size_t>(d));
    }
}

TEST(iterator, increment) {
    auto randeng = std::default_random_engine();
    {
        SCOPED_TRACE("empty tree");
        tree_t tree;
        auto it = tree.begin();
        ASSERT_EQ(tree.begin(), it);
        ASSERT_EQ(tree.end(), it);
        ASSERT_NO_THROW(it++);
        ASSERT_NO_THROW(++it);
    }
    {
        SCOPED_TRACE("non empty tree");
        tree_t tree;
        std::vector<std::string> unique_keys = get_unique_keys();
        std::set<std::string> keys;
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
                keys.insert(key);
            }
        }
        {
            SCOPED_TRACE("postincrement");
            for (auto it = tree.begin(); it != tree.end();) {
                ASSERT_NE(keys.end(), keys.find(it->first));
                auto copy = it++;
                ASSERT_NE(copy, it);
            }
        }
        {
            SCOPED_TRACE("preincrement");
            for (auto it = tree.begin(); it != tree.end();) {
                ASSERT_NE(keys.end(), keys.find(it->first));
                ASSERT_NE(keys.end(), keys.find((*it).first));
                auto copy = ++it;
                ASSERT_EQ(copy, it);
            }
        }
    }
}

TEST(iterator, std__copy) {
    auto randeng = std::default_random_engine();
    SCOPED_TRACE("non empty tree");
    tree_t tree;
    {
        std::vector<std::string> unique_keys = get_unique_keys();
        // fill tree with some data
        std::ranges::shuffle(unique_keys, randeng);
        for (const auto& key : unique_keys) {
            tree.insert(tree_t::value_type(key, randeng() % 100));
        }
    }
    std::map<std::string, int> map;
    std::copy(tree.begin(), tree.end(), std::inserter(map, map.end()));

    auto d = std::distance<tree_t::iterator>(tree.begin(), tree.end());
    ASSERT_EQ(map.size(), static_cast<size_t>(d));
    for (auto it = tree.begin(); it != tree.end(); ++it) {
        ASSERT_NE(map.end(), map.find(it->first));
    }
}
