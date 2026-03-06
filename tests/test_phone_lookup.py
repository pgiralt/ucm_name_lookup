"""Tests for phone number normalization, PrefixTrie, and directory lookup."""

import main


# ===========================================================================
# normalize_phone_number
# ===========================================================================

class TestNormalizePhoneNumber:
    def test_e164_with_formatting(self):
        assert main.normalize_phone_number("+1 (212) 555-1212") == "+12125551212"

    def test_plain_digits(self):
        assert main.normalize_phone_number("12125551212") == "12125551212"

    def test_leading_plus_preserved(self):
        assert main.normalize_phone_number("+12125551212") == "+12125551212"

    def test_dots_removed(self):
        assert main.normalize_phone_number("1.212.555.1212") == "12125551212"

    def test_empty_string(self):
        assert main.normalize_phone_number("") == ""

    def test_whitespace_only(self):
        assert main.normalize_phone_number("   ") == ""

    def test_already_normalized(self):
        assert main.normalize_phone_number("5551212") == "5551212"


# ===========================================================================
# PrefixTrie
# ===========================================================================

class TestPrefixTrie:
    def test_insert_and_exact_lookup(self):
        trie = main.PrefixTrie()
        trie.insert("+1212", "New York City")
        assert trie.longest_prefix_match("+12125551001") == "New York City"

    def test_longest_prefix_wins(self):
        trie = main.PrefixTrie()
        trie.insert("+1919", "North Carolina")
        trie.insert("+1919476", "RTP, NC")
        assert trie.longest_prefix_match("+19194761234") == "RTP, NC"
        assert trie.longest_prefix_match("+19195551234") == "North Carolina"

    def test_no_match(self):
        trie = main.PrefixTrie()
        trie.insert("+1212", "New York City")
        assert trie.longest_prefix_match("+1312999") is None

    def test_empty_trie(self):
        trie = main.PrefixTrie()
        assert trie.longest_prefix_match("+12125551001") is None

    def test_len(self):
        trie = main.PrefixTrie()
        assert len(trie) == 0
        trie.insert("+1212", "NYC")
        trie.insert("+1312", "Chicago")
        assert len(trie) == 2

    def test_exact_prefix_boundary(self):
        trie = main.PrefixTrie()
        trie.insert("123", "Match")
        assert trie.longest_prefix_match("123") == "Match"
        assert trie.longest_prefix_match("1234") == "Match"
        assert trie.longest_prefix_match("12") is None


# ===========================================================================
# load_phone_directory
# ===========================================================================

class TestLoadPhoneDirectory:
    def test_loads_test_fixture(self):
        """The test CSV should have been loaded at import time."""
        assert len(main.exact_directory) > 0
        assert main.prefix_trie is not None
        assert len(main.prefix_trie) > 0

    def test_exact_entries_loaded(self):
        assert "+12125551001" in main.exact_directory
        assert main.exact_directory["+12125551001"] == "Alice Johnson"

    def test_prefix_entries_loaded(self):
        assert main.prefix_trie is not None
        assert main.prefix_trie.longest_prefix_match("+12125559999") == "New York City"

    def test_missing_csv_raises(self):
        import pytest
        with pytest.raises(FileNotFoundError):
            main.load_phone_directory("/nonexistent/path.csv")


# ===========================================================================
# lookup_display_name
# ===========================================================================

class TestLookupDisplayName:
    def test_exact_match(self):
        assert main.lookup_display_name("+12125551001") == "Alice Johnson"

    def test_exact_match_with_formatting(self):
        assert main.lookup_display_name("+1 (212) 555-1001") == "Alice Johnson"

    def test_prefix_match(self):
        assert main.lookup_display_name("+13129999999") == "Chicago"

    def test_longest_prefix_match(self):
        assert main.lookup_display_name("+19194761234") == "RTP, NC"

    def test_no_match_returns_none(self):
        assert main.lookup_display_name("+99999999999") is None

    def test_exact_takes_priority_over_prefix(self):
        assert main.lookup_display_name("+12125551001") == "Alice Johnson"
        assert main.lookup_display_name("+12125559999") == "New York City"
