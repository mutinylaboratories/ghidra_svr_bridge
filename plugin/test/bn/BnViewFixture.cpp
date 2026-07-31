#include "BnViewFixture.h"
#include <cstdio>

using namespace BinaryNinja;

namespace bn_fixture {

std::string fixtureBinPath() {
    return testDataDir() + "/bin/parity_x64.bin";
}

Ref<BinaryView> makeViewAt(uint64_t imageBase) {
    // Linear sweep / signature matching are disabled: they nondeterministically
    // discover the fixture's thunk stub and pollute symbol-set assertions.
    // Tests create every function they assert on explicitly.
    char options[512];
    snprintf(options, sizeof(options),
             "{\"loader.imageBase\": %llu, "
             "\"loader.platform\": \"windows-x86_64\", "
             "\"analysis.linearSweep.autorun\": false, "
             "\"analysis.signatureMatcher.autorun\": false}",
             (unsigned long long)imageBase);
    Ref<BinaryView> view = Load(fixtureBinPath(), /*updateAnalysis=*/true, options);
    if (view && view->GetTypeName() == "Raw")
        return nullptr;  // Mapped loader didn't engage
    return view;
}

Ref<BinaryView> makeView() {
    return makeViewAt(kDefaultBase);
}

Ref<BinaryView> saveAndReopen(Ref<BinaryView> view, const std::string& bndbPath) {
    if (!view)
        return nullptr;
    if (!view->CreateDatabase(bndbPath))
        return nullptr;
    closeView(view);
    return Load(bndbPath, /*updateAnalysis=*/true);
}

void closeView(Ref<BinaryView> view) {
    if (!view)
        return;
    Ref<FileMetadata> file = view->GetFile();
    if (file)
        file->Close();
}

} // namespace bn_fixture
