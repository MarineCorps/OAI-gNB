
#include "common.hpp"

TEST(erase, change_size) {
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
        {
            SCOPED_TRACE("try to erase every key");
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                const size_t size_before_erase = tree.size();
                tree.erase(key);
                ASSERT_EQ(size_before_erase - 1, tree.size());
            }
            ASSERT_EQ(0u, tree.size());
        }
    }
}

TEST(erase, success_if_key_exist_fail_if_no_such_key) {
    auto randeng = std::default_random_engine();
    std::vector<std::string> unique_keys = get_unique_keys();
    for (size_t i = 0; i < unique_keys.size(); i++) {
        tree_t tree;
        {
            SCOPED_TRACE("try to erase keys never inserted before");
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                const bool erased = tree.erase(key);
                ASSERT_FALSE(erased);
            }
        }
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }
        {
            SCOPED_TRACE("try to erase existent key");
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                const bool erased = tree.erase(key);
                ASSERT_TRUE(erased);
            }
        }
        {
            SCOPED_TRACE("try to erase already removed key");
            for (const auto& key : unique_keys) {
                const bool erased = tree.erase(key);
                ASSERT_FALSE(erased);
            }
        }
    }
}

TEST(erase, not_greedy) {
    tree_t tree;
    tree["bro"] = 1;
    tree["brother"] = 2;

    {
        SCOPED_TRACE("before erase");
        vector_found_t vec;
        tree.prefix_match("bro", vec);
        map_found_t should_be_found;
        should_be_found["bro"] = 1;
        should_be_found["brother"] = 2;
        ASSERT_EQ(should_be_found, vec_found_to_map(vec));
    }
    {
        SCOPED_TRACE("after erase");
        tree.erase("bro");
        vector_found_t vec;
        tree.prefix_match("bro", vec);
        map_found_t should_be_found;
        should_be_found["brother"] = 2;
        ASSERT_EQ(should_be_found, vec_found_to_map(vec));
    }
}

TEST(erase, empty_key) {
    auto randeng = std::default_random_engine();
    {
        SCOPED_TRACE("tree contains only empty key");
        tree_t tree;
        tree[""] = 1;
        const bool erased = tree.erase("");
        ASSERT_TRUE(erased);
        ASSERT_EQ(tree.end(), tree.find(""));
    }
    {
        SCOPED_TRACE("tree contains not only empty key");
        std::vector<std::string> unique_keys = get_unique_keys();
        tree_t tree;
        { // fill tree with some data
            std::ranges::shuffle(unique_keys, randeng);
            for (const auto& key : unique_keys) {
                tree.insert(tree_t::value_type(key, randeng() % 100));
            }
        }

        tree[""] = 1;
        const bool erased = tree.erase("");
        ASSERT_TRUE(erased);
        ASSERT_EQ(tree.end(), tree.find(""));

        for (const auto& key : unique_keys) {
            ASSERT_NE(tree.end(), tree.find(key));
            const bool key_erased = tree.erase(key);
            ASSERT_TRUE(key_erased);
        }
    }
}
