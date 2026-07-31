#pragma once
#include "BnTestSupport.h"
#include <binaryninjaapi.h>
#include <cstdint>
#include <string>

// Loads testdata/bin/parity_x64.bin into a fresh BinaryView with the Mapped
// loader — pinned platform + image base, analysis updated. Each call returns
// an independent view; callers own closing it via closeView() (which also
// deletes the temp file for views reopened from a .bndb).
namespace bn_fixture {

constexpr uint64_t kDefaultBase = 0x400000;

// Fixture layout offsets (see testdata/bin/parity_x64.md).
constexpr uint64_t kOffFuncRet    = 0x000;
constexpr uint64_t kOffFuncEquate = 0x010;
constexpr uint64_t kOffFuncFrame  = 0x020;
constexpr uint64_t kOffFuncThunk  = 0x040;
constexpr uint64_t kOffFuncNoRet  = 0x050;
constexpr uint64_t kOffDataPoint  = 0x100;
constexpr uint64_t kOffDataInt    = 0x110;
constexpr uint64_t kOffDataStr    = 0x120;

/** Path to testdata/bin/parity_x64.bin. */
std::string fixtureBinPath();

/**
 * Load the fixture blob at @p imageBase. Returns nullptr on failure (callers
 * should ASSERT on it). The view has analysis settled but NO functions —
 * tests create exactly the functions they assert on.
 */
BinaryNinja::Ref<BinaryNinja::BinaryView> makeViewAt(uint64_t imageBase);

/** makeViewAt(kDefaultBase). */
BinaryNinja::Ref<BinaryNinja::BinaryView> makeView();

/**
 * Save @p view to @p bndbPath (.bndb), close it, and reopen the database.
 * Returns the reopened view, or nullptr on any failure.
 */
BinaryNinja::Ref<BinaryNinja::BinaryView>
saveAndReopen(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
              const std::string& bndbPath);

/** Close a view's file. Safe on nullptr. */
void closeView(BinaryNinja::Ref<BinaryNinja::BinaryView> view);

} // namespace bn_fixture
