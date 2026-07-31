#include <binaryninjaapi.h>
#include <ui/sidebar.h>
#include <ui/uitypes.h>
#include <ui/viewframe.h>

#include "GhidraConnection.h"
#include "ui/ProjectPanel.h"

#include <QImage>

// Ghidra dragon icon (64×64 PNG, extracted from Ghidra's Gui.jar).
// Ghidra is Apache 2.0 licensed — bundling its artwork is permitted.
#include "ghidra_icon64.h"

using namespace BinaryNinja;

// ---------------------------------------------------------------------------
// Sidebar type — registered once; BN creates one ProjectPanel per pane
// ---------------------------------------------------------------------------

static QImage makeSidebarIcon() {
    QImage img;
    img.loadFromData(kGhidraIcon64, static_cast<int>(kGhidraIcon64_len), "PNG");
    return img;
}

class GhidraSidebarType : public SidebarWidgetType {
public:
    GhidraSidebarType()
        : SidebarWidgetType(makeSidebarIcon(), "Ghidra") {}

    // Return false so the panel is available on the BN start page,
    // without requiring an open binary view.
    bool viewSensitive() const override { return false; }

    SidebarWidget* createWidget(ViewFrame* /*frame*/, BinaryViewRef /*data*/) override {
        return new ProjectPanel();
    }
};

// ---------------------------------------------------------------------------
// Plugin init
// ---------------------------------------------------------------------------

BN_DECLARE_CORE_ABI_VERSION

extern "C" BINARYNINJAPLUGIN bool CorePluginInit() {
    // ---- Register settings -------------------------------------------------
    auto settings = Settings::Instance();

    settings->RegisterGroup("ghidra", "Ghidra Integration");

    // ---- Bridge mode -------------------------------------------------------

    settings->RegisterSetting("ghidra.bridgeMode", R"json({
        "title"       : "Bridge Mode",
        "type"        : "string",
        "default"     : "local",
        "enum"        : ["local", "remote"],
        "enumDescriptions" : [
            "Local — spawn the bridge JAR as a child process on this machine (requires Java + Ghidra installed locally)",
            "Remote — connect to a bridge service running on the Ghidra server machine (see server/start-bridge.sh)"
        ],
        "description" : "How Binary Ninja connects to the Ghidra bridge. 'local' is easiest for single-machine setups; 'remote' keeps Java off the BN client machine.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    // ---- Local mode settings -----------------------------------------------

    settings->RegisterSetting("ghidra.javaExe", R"json({
        "title"       : "Java Executable (local mode)",
        "type"        : "string",
        "default"     : "java",
        "description" : "Path to the java executable used to launch the local bridge. Leave blank to use 'java' from PATH.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.ghidraHome", R"json({
        "title"       : "Ghidra Installation Directory (local mode)",
        "type"        : "string",
        "default"     : "",
        "description" : "Root directory of the local Ghidra installation (contains Ghidra/Framework/...). Leave blank to auto-detect.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.bridgeJar", R"json({
        "title"       : "Bridge JAR Path (local mode)",
        "type"        : "string",
        "default"     : "",
        "description" : "Path to ghidra-bridge-*.jar. Leave blank to look next to this plugin.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.trustAllCerts", R"json({
        "title"       : "Trust All SSL Certificates (local mode)",
        "type"        : "boolean",
        "default"     : false,
        "description" : "Disable SSL certificate validation for the local bridge. Use only on trusted networks.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.autoStartBridge", R"json({
        "title"       : "Auto-start Bridge on Launch (local mode)",
        "type"        : "boolean",
        "default"     : true,
        "description" : "In local mode, start the bridge process automatically when Binary Ninja launches so it is warm by the time you click Connect.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    // ---- Remote mode settings ----------------------------------------------

    settings->RegisterSetting("ghidra.bridgePort", R"json({
        "title"       : "Bridge Port (remote mode)",
        "type"        : "number",
        "default"     : 13200,
        "description" : "TCP port the bridge service is listening on (on the Ghidra server machine). Start the bridge with server/start-bridge.sh. The bridge host is always the same as the Ghidra server host entered in the Connect dialog.",
        "ignore"      : ["SettingsProjectScope", "SettingsResourceScope"]
    })json");

    // ---- Connection defaults -----------------------------------------------

    settings->RegisterSetting("ghidra.defaultHost", R"json({
        "title"       : "Default Server Host",
        "type"        : "string",
        "default"     : "localhost",
        "description" : "Pre-fill the Connect dialog with this host.",
        "ignore"      : ["SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.defaultPort", R"json({
        "title"       : "Default Server Port",
        "type"        : "number",
        "default"     : 13100,
        "description" : "Pre-fill the Connect dialog with this port.",
        "ignore"      : ["SettingsResourceScope"]
    })json");

    settings->RegisterSetting("ghidra.defaultUser", R"json({
        "title"       : "Default Username",
        "type"        : "string",
        "default"     : "",
        "description" : "Pre-fill the Connect dialog with this username.",
        "ignore"      : ["SettingsResourceScope"]
    })json");

    // ---- Register sidebar --------------------------------------------------
    Sidebar::addSidebarWidgetType(new GhidraSidebarType());

    // ---- Eagerly start local bridge in background --------------------------
    // Only in local mode. The JVM takes 1-3 s to boot; starting now means it
    // is ready by the time the user opens the sidebar and clicks Connect.
    if (settings->Get<std::string>("ghidra.bridgeMode") == "local" &&
        settings->Get<bool>("ghidra.autoStartBridge")) {
        WorkerEnqueue([] {
            auto& conn = GhidraConnection::instance();
            std::string err;
            if (!conn.connectBridge("127.0.0.1", err))
                LogWarn("Ghidra: local bridge failed to start: %s", err.c_str());
        });
    }

    return true;
}
