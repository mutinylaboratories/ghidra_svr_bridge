#pragma once
#include <QString>
#include <QPointer>
#include <memory>
#include <ui/sidebarwidget.h>
#include <ui/uitypes.h>
#include <binaryninjaapi.h>
#include "GhidraConnection.h"

// Forward declarations
class QLabel;
class QPushButton;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class ViewFrame;

/**
 * Sidebar panel: repo browser + live activity feed.
 *
 * Registered as a BinaryNinja::SidebarWidget.  The GhidraConnection is a
 * singleton so all open panels share the same server connection.
 *
 * UI thread safety: GhidraConnection invokes events on the bridge receive
 * thread.  We forward them to the Qt main thread with QueuedConnection so
 * all Qt widget updates happen on the correct thread.
 */
class ProjectPanel : public SidebarWidget {
    Q_OBJECT

    // -----------------------------------------------------------------------
    // Watches the active BN project for file additions / deletions so the
    // Project Files panel stays in sync without requiring a view change.
    // -----------------------------------------------------------------------
    class ProjectFileWatcher : public BinaryNinja::ProjectNotification {
        QPointer<ProjectPanel> m_panel;
        void notify();
    public:
        explicit ProjectFileWatcher(ProjectPanel* p) : m_panel(p) {}
        void OnAfterProjectFileCreated(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override { notify(); }
        void OnAfterProjectFileUpdated(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override { notify(); }
        void OnAfterProjectFileDeleted(BinaryNinja::Project*, BinaryNinja::ProjectFile*) override { notify(); }
    };

public:
    explicit ProjectPanel(QWidget* parent = nullptr);
    ~ProjectPanel();

    /** Called by BN when the active view frame changes. */
    void notifyViewChanged(ViewFrame* frame) override;

private slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onRefreshClicked();
    void onTreeContextMenu(const QPoint& pos);
    void onRepoItemExpanded(QTreeWidgetItem* item);
    void onRepoItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onProjectItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onEventReceived(GhidraEvent evt);
    void onProjectContextMenu(const QPoint& pos);
    void refreshStatus();

private:
    QLabel*       m_statusLabel       = nullptr;
    QPushButton*  m_connectBtn        = nullptr;
    QPushButton*  m_disconnectBtn     = nullptr;
    QPushButton*  m_refreshBtn        = nullptr;
    QWidget*      m_projectSection    = nullptr;  ///< Hidden when no project is open
    QTreeWidget*  m_projectTree       = nullptr;
    QTreeWidget*  m_repoTree          = nullptr;

    /// Non-blocking notice shown when the open view is linked to a Ghidra item
    /// but we are not connected to that server — offers "Connect & check".
    QWidget*      m_linkBanner        = nullptr;
    QLabel*       m_linkBannerLabel   = nullptr;

    /// Debounce timer: coalesces rapid refreshProjectFiles() calls into one.
    QTimer*       m_refreshTimer      = nullptr;
    /// Debounce timer: coalesces rapid refreshStatus() calls into one.
    QTimer*       m_statusTimer       = nullptr;
    /// Incremented every time populateRepos() clears the tree.  expandFolder()
    /// callbacks capture this value and no-op if it has changed by the time they
    /// run, preventing stale callbacks from writing into a freshly-rebuilt tree.
    int           m_treeGeneration    = 0;

    BinaryViewRef m_currentView;

    // Active project watcher — keeps the Project Files panel live.
    BinaryNinja::Ref<BinaryNinja::Project>  m_watchedProject;
    std::unique_ptr<ProjectFileWatcher>     m_projectWatcher;
    void watchProject(BinaryNinja::Ref<BinaryNinja::Project> project);
    void unwatchProject();

    // True while we know the linked Ghidra item is checked out by the current
    // user.  Set after upload-with-keep-checkout and cleared after a successful
    // check-in or explicit checkout termination.  Drives the context menu choice
    // between "Check In…" (checkout active) and "Check Out…" (no active checkout).
    bool m_checkedOut = false;

    // Ghidra link stored in the current .bndb's metadata.
    struct GhidraLink {
        QString host, user, repo, folder, item;
        int     port = 0;
        bool    valid() const { return !host.isEmpty() && !item.isEmpty(); }
    };
    GhidraLink m_linkedGhidra;

    /** Assign m_checkedOut and persist the value to project metadata. UI thread only. */
    void persistCheckedOutState(bool val);
    /** Show/hide the "linked to Ghidra" banner based on link + connection state. */
    void updateLinkBanner();
    /** Banner action: connect to the linked file's server (credentials preloaded)
     *  and report the linked item's latest version on the server. */
    void connectAndCheckLinked();
    /**
     * Debounced wrapper around refreshStatus(): coalesces multiple rapid calls
     * (e.g. from repeated notifyViewChanged() firings during analysis) into a
     * single server round-trip 200 ms after the last call.
     */
    void scheduleRefreshStatus();
    void buildUi();
    void updateConnectionButtons(bool connected);
    void populateRepos(const std::vector<std::string>& repos);
    void expandFolder(QTreeWidgetItem* item, const std::string& repo,
                      const std::string& folder);
    void importItem(const std::string& repo, const std::string& folder,
                    const std::string& name);
    void doCheckin();
    /** Called once check-in state is confirmed to be loaded. */
    void doCheckinWithState();
    void showHistory(const QString& repo, const QString& folder, const QString& name);
    void downloadBinary(const QString& repo, const QString& folder, const QString& name);
    void openItemIntoNewView(const QString& repo, const QString& folder, const QString& name);
    /**
     * Persistent (QSettings-backed, keyed by server host:port + repo path) map
     * from a Ghidra item to the local file the user last opened for it, so
     * "Open" reuses the associated .bndb instead of prompting every time.
     * Stored in the OS settings store (registry / plist) — no file to manage.
     */
    static QString recordedPathForItem(const QString& repo, const QString& folder,
                                       const QString& name);
    static void    recordPathForItem(const QString& repo, const QString& folder,
                                     const QString& name, const QString& path);
    /**
     * Project-aware double-click handler: checks whether @p repo/@p folder/@p name
     * already exists in the open BN project (opens it), or downloads the binary,
     * adds it to the project, stores Ghidra link metadata, and opens it so that
     * notifyViewChanged auto-imports symbols.  Falls back to openItemIntoNewView
     * if no project is open.
     */
    void addItemToProject(const QString& repo, const QString& folder, const QString& name);
    /** A Ghidra repository item, used for the multi-select bulk add. */
    struct RepoItemRef { QString repo, folder, name; };
    /**
     * Download each selected Ghidra item and add it to the current BN project
     * WITHOUT opening it, storing the per-file "ghidra.link.<fileId>" metadata.
     * Skips items already present.  Backs the "Add N items to project" action.
     */
    void bulkAddItemsToProject(const std::vector<RepoItemRef>& items);
    /**
     * Core of the bulk/new-project add: on a background worker, download each
     * item and add it to @p project (root folder), store "ghidra.server" +
     * "ghidra.link.<fileId>" metadata, then run @p onDone(added, failed) on the
     * UI thread.  Items already present are the caller's responsibility to skip.
     */
    void populateProjectWithItems(BinaryNinja::Ref<BinaryNinja::Project> project,
                                  std::vector<RepoItemRef> items,
                                  std::function<void(int added, int failed)> onDone);
    /**
     * Context action from a repo/folder node: recursively enumerate its items,
     * show a checklist to pick which ones, then create a NEW BN project at a
     * user-chosen path, populate it with the selected items, and open it.
     */
    void createProjectFromNode(const QString& repo, const QString& folder,
                               const QString& label);
    QTreeWidgetItem* findTreeItem(const QString& repo, const QString& folder,
                                  const QString& name) const;
    void setItemCheckedOut(QTreeWidgetItem* item, bool checkedOut);
    void addActivityEntry(const QString& text);
    void logError(const QString& msg);

    /** Rebuild the Project Files section from the current BN project (if any). */
    void refreshProjectFiles();
    /**
     * Schedule a debounced refresh: if called multiple times within 150 ms
     * (e.g. from the ProjectFileWatcher + the importItem callback + notifyViewChanged)
     * only one actual refreshProjectFiles() call is made.
     */
    void scheduleRefreshProjectFiles();
    /**
     * If the currently open file is inside a BN project but its Ghidra link
     * exists only in the .bndb metadata (imported before the project existed),
     * promote that data into the project-level metadata so it shows up in the
     * Project Files panel alongside other files.
     */
    void migrateStandaloneMetadata();
    /**
     * Upload the binary at @p filePath to the Ghidra server as a new repository
     * item and store the resulting Ghidra link in the BN project metadata.
     * @p projectFileId identifies the BN ProjectFile to tag with the link.
     */
    void uploadToGhidra(const QString& filePath,
                        const QString& fileName,
                        const QString& projectFileId);
};
