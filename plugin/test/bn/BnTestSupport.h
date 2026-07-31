#pragma once
#include <gtest/gtest.h>
#include <string>

// Set by BnTestMain.cpp after headless core initialization succeeds.
// Tests must not touch any BN API when this is false.
extern bool g_bnCoreReady;

// Absolute path to the repo's testdata/ directory (from PARITY_TESTDATA_DIR).
std::string testDataDir();

// Skip (not fail) when the machine can't run headless BN — no install on
// PATH, or the license doesn't permit headless use.
#define BN_REQUIRE_CORE()                                                     \
    do {                                                                      \
        if (!g_bnCoreReady)                                                   \
            GTEST_SKIP() << "BN headless core unavailable (no install/license)"; \
    } while (0)
