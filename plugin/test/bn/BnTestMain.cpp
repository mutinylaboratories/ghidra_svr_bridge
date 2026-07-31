// BnTestMain.cpp — custom gtest main for the BN-headless test tier.
//
// Initializes binaryninjacore in headless mode once per process. When the
// core can't come up (no BN install on PATH, or the license doesn't allow
// headless), g_bnCoreReady stays false and every test using BN_REQUIRE_CORE()
// reports SKIPPED instead of failing, so this target is safe to run anywhere.

#include <gtest/gtest.h>
#include <binaryninjaapi.h>
#include <cstdlib>
#include <cstring>
#include <string>

bool g_bnCoreReady = false;

std::string testDataDir() {
#ifdef PARITY_TESTDATA_DIR
    return PARITY_TESTDATA_DIR;
#else
    return "testdata";
#endif
}

int main(int argc, char** argv) {
    // gtest_discover_tests runs `exe --gtest_list_tests` at build/test time;
    // don't spin up the core just to enumerate test names. Check before
    // InitGoogleTest — it strips recognized flags from argv.
    bool listOnly = false;
    for (int i = 1; i < argc; ++i)
        if (std::strncmp(argv[i], "--gtest_list_tests", 18) == 0)
            listOnly = true;

    ::testing::InitGoogleTest(&argc, argv);

    if (!listOnly) {
        try {
            if (const char* lic = std::getenv("BN_LICENSE"))
                BNSetLicense(lic);
            BinaryNinja::SetBundledPluginDirectory(
                BinaryNinja::GetBundledPluginDirectory());
            g_bnCoreReady = BinaryNinja::InitPlugins();
        } catch (...) {
            g_bnCoreReady = false;
        }
        if (!g_bnCoreReady)
            fprintf(stderr, "warning: BN headless init failed — "
                            "BN-dependent tests will be skipped\n");
    }

    int rc = RUN_ALL_TESTS();

    if (g_bnCoreReady)
        BNShutdown();
    return rc;
}
