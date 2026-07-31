// enterprise_stubs.cpp
//
// Weak stub implementations for Enterprise / Collaboration API functions.
// These satisfy the static linker when building against standard (non-Enterprise)
// Binary Ninja: the binaryninjaapi static library contains collaboration/enterprise
// wrapper code that references these BN* core functions, but a commercial (non-
// Enterprise) Binary Ninja core does not export them.  This plugin uses none of
// these APIs itself; the stubs exist purely to resolve the link.
//
// Weak-symbol portability:
//   GCC/Clang: __attribute__((weak)) lets the real libbinaryninjacore symbols
//     take precedence at link/run time when running on Enterprise BN.
//   MSVC: has no weak-function attribute.  A commercial BN core does not export
//     these symbols (they appear as *unresolved* externals without this file, never
//     as duplicates), so on MSVC we define them as ordinary strong symbols — there
//     is nothing for them to collide with.  Building against an *Enterprise* core
//     on Windows would instead need /alternatename linker directives; that is out
//     of scope here, since the plugin targets commercial licenses.
//
// Auto-generated from binaryninjacore.h + collaboration.cpp + enterprise.cpp

#include "binaryninjacore.h"

// Suppress unused-parameter warnings inside stub bodies
#if defined(__GNUC__) || defined(__clang__)
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  define BN_WEAK __attribute__((weak))
#else
#  define BN_WEAK
#endif

// All BN* functions have C linkage (declared extern "C" in binaryninjacore.h).
// Definitions must match — wrap in extern "C" so the linker sees the same mangled
// names as the declarations.
extern "C" {

BN_WEAK char* BNAnalysisMergeConflictGetBase(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNFileMetadata* BNAnalysisMergeConflictGetBaseFile(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNSnapshot* BNAnalysisMergeConflictGetBaseSnapshot(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNMergeConflictDataType BNAnalysisMergeConflictGetDataType(BNAnalysisMergeConflict* conflict) { return (BNMergeConflictDataType)0; }
BN_WEAK char* BNAnalysisMergeConflictGetFirst(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNFileMetadata* BNAnalysisMergeConflictGetFirstFile(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNSnapshot* BNAnalysisMergeConflictGetFirstSnapshot(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK void* BNAnalysisMergeConflictGetPathItem(BNAnalysisMergeConflict* conflict, const char* path) { return NULL; }
BN_WEAK char* BNAnalysisMergeConflictGetPathItemSerialized(BNAnalysisMergeConflict* conflict, const char* path) { return NULL; }
BN_WEAK char* BNAnalysisMergeConflictGetPathItemString(BNAnalysisMergeConflict* conflict, const char* path) { return NULL; }
BN_WEAK char* BNAnalysisMergeConflictGetSecond(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNFileMetadata* BNAnalysisMergeConflictGetSecondFile(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK BNSnapshot* BNAnalysisMergeConflictGetSecondSnapshot(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK char* BNAnalysisMergeConflictGetType(BNAnalysisMergeConflict* conflict) { return NULL; }
BN_WEAK bool BNAnalysisMergeConflictSuccess(BNAnalysisMergeConflict* conflict, const char* value) { return false; }
BN_WEAK bool BNAuthenticateEnterpriseServerWithCredentials(const char* username, const char* password, bool remember) { return false; }
BN_WEAK bool BNAuthenticateEnterpriseServerWithMethod(const char* method, bool remember) { return false; }
BN_WEAK void BNCancelEnterpriseServerAuthentication(void) { (void)0; }
BN_WEAK bool BNCollaborationAssignSnapshotMap(BNSnapshot* localSnapshot, BNCollaborationSnapshot* remoteSnapshot) { return false; }
BN_WEAK BNCollaborationUser* BNCollaborationChangesetGetAuthor(BNCollaborationChangeset* changeset) { return NULL; }
BN_WEAK BNDatabase* BNCollaborationChangesetGetDatabase(BNCollaborationChangeset* changeset) { return NULL; }
BN_WEAK BNRemoteFile* BNCollaborationChangesetGetFile(BNCollaborationChangeset* changeset) { return NULL; }
BN_WEAK char* BNCollaborationChangesetGetName(BNCollaborationChangeset* changeset) { return NULL; }
BN_WEAK int64_t* BNCollaborationChangesetGetSnapshotIds(BNCollaborationChangeset* changeset, size_t* count) { return NULL; }
BN_WEAK bool BNCollaborationChangesetSetName(BNCollaborationChangeset* changeset, const char* name) { return false; }
BN_WEAK BNRemote* BNCollaborationCreateRemote(const char* name, const char* address) { return NULL; }
BN_WEAK char* BNCollaborationDefaultFilePath(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNCollaborationDefaultProjectPath(BNRemoteProject* project) { return NULL; }
BN_WEAK bool BNCollaborationDeleteDataFromKeychain(const char* key) { return false; }
BN_WEAK bool BNCollaborationDownloadDatabaseForFile(BNRemoteFile* file, const char* dbPath, bool force, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK BNFileMetadata* BNCollaborationDownloadFile(BNRemoteFile* file, const char* dbPath, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK bool BNCollaborationDownloadTypeArchive(BNRemoteFile* file, const char* dbPath, BNProgressFunction progress, void* progressContext, BNTypeArchive** result) { return false; }
BN_WEAK bool BNCollaborationDumpDatabase(BNDatabase* database) { return false; }
BN_WEAK BNRemote* BNCollaborationGetActiveRemote(void) { return NULL; }
BN_WEAK size_t BNCollaborationGetDataFromKeychain(const char* key, char*** foundKeys, char*** foundValues) { return 0; }
BN_WEAK bool BNCollaborationGetLocalSnapshotFromRemote(BNCollaborationSnapshot* snapshot, BNDatabase* database, BNSnapshot** result) { return false; }
BN_WEAK char* BNCollaborationGetLocalSnapshotFromRemoteTypeArchive(BNCollaborationSnapshot* snapshot, BNTypeArchive* archive) { return NULL; }
BN_WEAK BNRemote* BNCollaborationGetRemoteByAddress(const char* remoteAddress) { return NULL; }
BN_WEAK BNRemote* BNCollaborationGetRemoteById(const char* remoteId) { return NULL; }
BN_WEAK BNRemote* BNCollaborationGetRemoteByName(const char* name) { return NULL; }
BN_WEAK bool BNCollaborationGetRemoteFileForLocalDatabase(BNDatabase* database, BNRemoteFile** result) { return false; }
BN_WEAK BNRemoteFile* BNCollaborationGetRemoteFileForLocalTypeArchive(BNTypeArchive* archive) { return NULL; }
BN_WEAK bool BNCollaborationGetRemoteForLocalDatabase(BNDatabase* database, BNRemote** result) { return false; }
BN_WEAK BNRemote* BNCollaborationGetRemoteForLocalTypeArchive(BNTypeArchive* archive) { return NULL; }
BN_WEAK bool BNCollaborationGetRemoteProjectForLocalDatabase(BNDatabase* database, BNRemoteProject** result) { return false; }
BN_WEAK BNRemoteProject* BNCollaborationGetRemoteProjectForLocalTypeArchive(BNTypeArchive* archive) { return NULL; }
BN_WEAK bool BNCollaborationGetRemoteSnapshotFromLocal(BNSnapshot* snapshot, BNCollaborationSnapshot** result) { return false; }
BN_WEAK BNCollaborationSnapshot* BNCollaborationGetRemoteSnapshotFromLocalTypeArchive(BNTypeArchive* archive, const char* snapshotId) { return NULL; }
BN_WEAK BNRemote** BNCollaborationGetRemotes(size_t* count) { return NULL; }
BN_WEAK bool BNCollaborationGetSnapshotAuthor(BNDatabase* database, BNSnapshot* snapshot, char** result) { return false; }
// --- Collaboration user API: several signatures changed after the ABI 164
//     (current stable) release.  ABI >= 165 (dev, and future stable releases)
//     uses BNCollaborationUser* / BNVersionInfo / char***; ABI 164 uses
//     const char* username.  Gating on BN_CURRENT_CORE_ABI_VERSION lets this
//     one stub file compile against both --channel stable and --channel dev. ---
#if BN_CURRENT_CORE_ABI_VERSION >= 165
BN_WEAK bool BNCollaborationGroupContainsUser(BNCollaborationGroup* group, BNCollaborationUser* user) { return false; }
#else
BN_WEAK bool BNCollaborationGroupContainsUser(BNCollaborationGroup* group, const char* username) { return false; }
#endif
BN_WEAK uint64_t BNCollaborationGroupGetId(BNCollaborationGroup* group) { return 0; }
BN_WEAK char* BNCollaborationGroupGetName(BNCollaborationGroup* group) { return NULL; }
BN_WEAK void BNCollaborationGroupSetName(BNCollaborationGroup* group, const char* name) { (void)0; }
#if BN_CURRENT_CORE_ABI_VERSION >= 165
BN_WEAK BNCollaborationUser** BNCollaborationGroupGetUsers(BNCollaborationGroup* group, size_t* count) { if (count) *count = 0; return NULL; }
#else
BN_WEAK bool BNCollaborationGroupGetUsers(BNCollaborationGroup* group, char*** userIds, char*** usernames, size_t* count) { if (count) *count = 0; return false; }
#endif
BN_WEAK bool BNCollaborationGroupSetUsers(BNCollaborationGroup* group, BNCollaborationUser** users, size_t count) { return false; }
BN_WEAK bool BNCollaborationGroupSetUsernames(BNCollaborationGroup* group, const char** names, size_t count) { return false; }
BN_WEAK bool BNCollaborationHasDataInKeychain(const char* key) { return false; }
BN_WEAK bool BNCollaborationIgnoreSnapshot(BNDatabase* database, BNSnapshot* snapshot) { return false; }
BN_WEAK bool BNCollaborationIsCollaborationDatabase(BNDatabase* database) { return false; }
BN_WEAK bool BNCollaborationIsCollaborationTypeArchive(BNTypeArchive* archive) { return false; }
BN_WEAK bool BNCollaborationIsSnapshotIgnored(BNDatabase* database, BNSnapshot* snapshot) { return false; }
BN_WEAK bool BNCollaborationIsTypeArchiveSnapshotIgnored(BNTypeArchive* archive, const char* snapshot) { return false; }
BN_WEAK bool BNCollaborationLoadRemotes(void) { return false; }
BN_WEAK bool BNCollaborationMergeDatabase(BNDatabase* database, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK BNSnapshot* BNCollaborationMergeSnapshots(BNSnapshot* first, BNSnapshot* second, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK bool BNCollaborationPermissionCanAdmin(BNCollaborationPermission* permission) { return false; }
BN_WEAK bool BNCollaborationPermissionCanEdit(BNCollaborationPermission* permission) { return false; }
BN_WEAK bool BNCollaborationPermissionCanView(BNCollaborationPermission* permission) { return false; }
BN_WEAK uint64_t BNCollaborationPermissionGetGroupId(BNCollaborationPermission* permission) { return 0; }
BN_WEAK char* BNCollaborationPermissionGetGroupName(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK char* BNCollaborationPermissionGetId(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK BNCollaborationPermissionLevel BNCollaborationPermissionGetLevel(BNCollaborationPermission* permission) { return (BNCollaborationPermissionLevel)0; }
BN_WEAK BNRemoteProject* BNCollaborationPermissionGetProject(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK BNRemote* BNCollaborationPermissionGetRemote(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK char* BNCollaborationPermissionGetUrl(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK char* BNCollaborationPermissionGetUserId(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK char* BNCollaborationPermissionGetUsername(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK void BNCollaborationPermissionSetLevel(BNCollaborationPermission* permission, BNCollaborationPermissionLevel level) { (void)0; }
BN_WEAK bool BNCollaborationPullDatabase(BNDatabase* database, BNRemoteFile* file, size_t* count, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressContext, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetContext) { return false; }
BN_WEAK bool BNCollaborationPullTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, size_t* count, bool(*conflictHandler)(void*, BNTypeArchiveMergeConflict** conflicts, size_t conflictCount), void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt) { return false; }
BN_WEAK bool BNCollaborationPushDatabase(BNDatabase* database, BNRemoteFile* file, size_t* count, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNCollaborationPushTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, size_t* count, BNProgressFunction progress, void* progressCtxt) { return false; }
BN_WEAK void BNCollaborationRemoveRemote(BNRemote* remote) { (void)0; }
BN_WEAK void BNCollaborationSetActiveRemote(BNRemote* remote) { (void)0; }
BN_WEAK bool BNCollaborationSetSnapshotAuthor(BNDatabase* database, BNSnapshot* snapshot, const char* author) { return false; }
BN_WEAK BNCollaborationUndoEntry* BNCollaborationSnapshotCreateUndoEntry(BNCollaborationSnapshot* snapshot, bool hasParent, uint64_t parent, const char* data) { return NULL; }
BN_WEAK bool BNCollaborationSnapshotDownload(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size) { return false; }
BN_WEAK bool BNCollaborationSnapshotDownloadAnalysisCache(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size) { return false; }
BN_WEAK bool BNCollaborationSnapshotDownloadSnapshotFile(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext, uint8_t** data, size_t* size) { return false; }
BN_WEAK bool BNCollaborationSnapshotFinalize(BNCollaborationSnapshot* snapshot) { return false; }
BN_WEAK uint64_t BNCollaborationSnapshotGetAnalysisCacheBuildId(BNCollaborationSnapshot* snapshot) { return 0; }
BN_WEAK char* BNCollaborationSnapshotGetAuthor(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetAuthorUsername(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK BNCollaborationSnapshot** BNCollaborationSnapshotGetChildren(BNCollaborationSnapshot* snapshot, size_t* count) { return NULL; }
BN_WEAK int64_t BNCollaborationSnapshotGetCreated(BNCollaborationSnapshot* snapshot) { return 0; }
BN_WEAK char* BNCollaborationSnapshotGetDescription(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK BNRemoteFile* BNCollaborationSnapshotGetFile(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetHash(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetId(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK int64_t BNCollaborationSnapshotGetLastModified(BNCollaborationSnapshot* snapshot) { return 0; }
BN_WEAK char* BNCollaborationSnapshotGetName(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char** BNCollaborationSnapshotGetParentIds(BNCollaborationSnapshot* snapshot, size_t* count) { return NULL; }
BN_WEAK BNCollaborationSnapshot** BNCollaborationSnapshotGetParents(BNCollaborationSnapshot* snapshot, size_t* count) { return NULL; }
BN_WEAK BNRemoteProject* BNCollaborationSnapshotGetProject(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK BNRemote* BNCollaborationSnapshotGetRemote(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetSnapshotFileHash(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetTitle(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK BNCollaborationUndoEntry** BNCollaborationSnapshotGetUndoEntries(BNCollaborationSnapshot* snapshot, size_t* count) { return NULL; }
BN_WEAK BNCollaborationUndoEntry* BNCollaborationSnapshotGetUndoEntryById(BNCollaborationSnapshot* snapshot, uint64_t id) { return NULL; }
BN_WEAK char* BNCollaborationSnapshotGetUrl(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK bool BNCollaborationSnapshotHasPulledUndoEntries(BNCollaborationSnapshot* snapshot) { return false; }
BN_WEAK bool BNCollaborationSnapshotIsFinalized(BNCollaborationSnapshot* snapshot) { return false; }
BN_WEAK bool BNCollaborationSnapshotPullUndoEntries(BNCollaborationSnapshot* snapshot, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNCollaborationStoreDataInKeychain(const char* key, const char** dataKeys, const char** dataValues, size_t dataCount) { return false; }
BN_WEAK bool BNCollaborationSyncDatabase(BNDatabase* database, BNRemoteFile* file, BNCollaborationAnalysisConflictHandler conflictHandler, void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetCtxt) { return false; }
BN_WEAK bool BNCollaborationSyncTypeArchive(BNTypeArchive* archive, BNRemoteFile* file, bool(*conflictHandler)(void*, BNTypeArchiveMergeConflict** conflicts, size_t conflictCount), void* conflictHandlerCtxt, BNProgressFunction progress, void* progressCtxt) { return false; }
BN_WEAK BNRemoteFile* BNCollaborationUploadDatabase(BNFileMetadata* metadata, BNRemoteProject* project, BNRemoteFolder* folder, BNProgressFunction progress, void* progressContext, BNCollaborationNameChangesetFunction nameChangeset, void* nameChangesetContext) { return NULL; }
BN_WEAK bool BNCollaborationUploadTypeArchive(BNTypeArchive* archive, BNRemoteProject* project, BNRemoteFolder* folder, BNProgressFunction progress, void* progressContext, BNProjectFile* coreFile, BNRemoteFile** result) { return false; }
BN_WEAK char* BNCollaborationUserGetEmail(BNCollaborationUser* user) { return NULL; }
BN_WEAK char* BNCollaborationUserGetId(BNCollaborationUser* user) { return NULL; }
BN_WEAK char* BNCollaborationUserGetLastLogin(BNCollaborationUser* user) { return NULL; }
BN_WEAK BNRemote* BNCollaborationUserGetRemote(BNCollaborationUser* user) { return NULL; }
BN_WEAK char* BNCollaborationUserGetUrl(BNCollaborationUser* user) { return NULL; }
BN_WEAK char* BNCollaborationUserGetUsername(BNCollaborationUser* user) { return NULL; }
BN_WEAK bool BNCollaborationUserIsActive(BNCollaborationUser* user) { return false; }
BN_WEAK bool BNCollaborationUserSetEmail(BNCollaborationUser* user, const char* email) { return false; }
BN_WEAK bool BNCollaborationUserSetIsActive(BNCollaborationUser* user, bool isActive) { return false; }
BN_WEAK bool BNCollaborationUserSetUsername(BNCollaborationUser* user, const char* username) { return false; }
BN_WEAK bool BNConnectEnterpriseServer(void) { return false; }
BN_WEAK bool BNDeauthenticateEnterpriseServer(void) { return false; }
BN_WEAK void BNFreeCollaborationGroupList(BNCollaborationGroup** group, size_t count) { (void)0; }
BN_WEAK void BNFreeCollaborationPermissionList(BNCollaborationPermission** permissions, size_t count) { (void)0; }
BN_WEAK void BNFreeCollaborationSnapshotList(BNCollaborationSnapshot** snapshots, size_t count) { (void)0; }
BN_WEAK void BNFreeCollaborationUndoEntryList(BNCollaborationUndoEntry** entries, size_t count) { (void)0; }
BN_WEAK void BNFreeCollaborationUserList(BNCollaborationUser** users, size_t count) { (void)0; }
BN_WEAK void BNFreeRemoteFileList(BNRemoteFile** files, size_t count) { (void)0; }
BN_WEAK void BNFreeRemoteFileSearchMatchList(BNRemoteFileSearchMatch* matches, size_t count) { (void)0; }
BN_WEAK void BNFreeRemoteFolderList(BNRemoteFolder** folders, size_t count) { (void)0; }
BN_WEAK void BNFreeRemoteList(BNRemote** remotes, size_t count) { (void)0; }
BN_WEAK void BNFreeRemoteProjectList(BNRemoteProject** projects, size_t count) { (void)0; }
BN_WEAK void BNFreeString(char* str) { (void)0; }
BN_WEAK void BNFreeStringList(char** strs, size_t count) { (void)0; }
BN_WEAK size_t BNGetEnterpriseServerAuthenticationMethods(char*** methods, char*** names) { return 0; }
BN_WEAK char* BNGetEnterpriseServerBuildId(void) { return NULL; }
BN_WEAK char* BNGetEnterpriseServerId(void) { return NULL; }
BN_WEAK char* BNGetEnterpriseServerLastError(void) { return NULL; }
BN_WEAK uint64_t BNGetEnterpriseServerLicenseDuration(void) { return 0; }
BN_WEAK uint64_t BNGetEnterpriseServerLicenseExpirationTime(void) { return 0; }
BN_WEAK char* BNGetEnterpriseServerName(void) { return NULL; }
BN_WEAK uint64_t BNGetEnterpriseServerReservationTimeLimit(void) { return 0; }
BN_WEAK char* BNGetEnterpriseServerToken(void) { return NULL; }
BN_WEAK char* BNGetEnterpriseServerUrl(void) { return NULL; }
BN_WEAK char* BNGetEnterpriseServerUsername(void) { return NULL; }
BN_WEAK uint64_t BNGetEnterpriseServerVersion(void) { return 0; }
BN_WEAK uint64_t BNGetLicenseExpirationTime(void) { return 0; }
BN_WEAK bool BNInitializeEnterpriseServer(void) { return false; }
BN_WEAK bool BNIsEnterpriseServerAuthenticated(void) { return false; }
BN_WEAK bool BNIsEnterpriseServerConnected(void) { return false; }
BN_WEAK bool BNIsEnterpriseServerFloatingLicense(void) { return false; }
BN_WEAK bool BNIsEnterpriseServerInitialized(void) { return false; }
BN_WEAK bool BNIsEnterpriseServerLicenseStillActivated(void) { return false; }
BN_WEAK bool BNIsUIEnabled(void) { return false; }
BN_WEAK BNCollaborationGroup* BNNewCollaborationGroupReference(BNCollaborationGroup* group) { return NULL; }
BN_WEAK BNCollaborationPermission* BNNewCollaborationPermissionReference(BNCollaborationPermission* permission) { return NULL; }
BN_WEAK BNCollaborationSnapshot* BNNewCollaborationSnapshotReference(BNCollaborationSnapshot* snapshot) { return NULL; }
BN_WEAK BNCollaborationUndoEntry* BNNewCollaborationUndoEntryReference(BNCollaborationUndoEntry* entry) { return NULL; }
BN_WEAK BNCollaborationUser* BNNewCollaborationUserReference(BNCollaborationUser* user) { return NULL; }
BN_WEAK BNRemoteFile* BNNewRemoteFileReference(BNRemoteFile* file) { return NULL; }
BN_WEAK BNRemoteFolder* BNNewRemoteFolderReference(BNRemoteFolder* folder) { return NULL; }
BN_WEAK BNRemoteProject* BNNewRemoteProjectReference(BNRemoteProject* project) { return NULL; }
BN_WEAK BNRemote* BNNewRemoteReference(BNRemote* remote) { return NULL; }
BN_WEAK void BNRegisterEnterpriseServerNotification(BNEnterpriseServerCallbacks* notify) { (void)0; }
BN_WEAK bool BNReleaseEnterpriseServerLicense(void) { return false; }
BN_WEAK bool BNRemoteConnect(BNRemote* remote, const char* username, const char* token) { return false; }
#if BN_CURRENT_CORE_ABI_VERSION >= 165
BN_WEAK BNCollaborationGroup* BNRemoteCreateGroup(BNRemote* remote, const char* name, BNCollaborationUser** users, size_t userCount) { return NULL; }
#else
BN_WEAK BNCollaborationGroup* BNRemoteCreateGroup(BNRemote* remote, const char* name, const char** usernames, size_t usernameCount) { return NULL; }
#endif
BN_WEAK BNRemoteProject* BNRemoteCreateProject(BNRemote* remote, const char* name, const char* description) { return NULL; }
BN_WEAK BNCollaborationUser* BNRemoteCreateUser(BNRemote* remote, const char* username, const char* email, bool isActive, const char* password, const uint64_t* groupIds, size_t groupIdCount, const uint64_t* userPermissionIds, size_t userPermissionIdCount) { return NULL; }
BN_WEAK bool BNRemoteDeleteGroup(BNRemote* remote, BNCollaborationGroup* group) { return false; }
BN_WEAK bool BNRemoteDeleteProject(BNRemote* remote, BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteDisconnect(BNRemote* remote) { return false; }
BN_WEAK BNCollaborationSnapshot* BNRemoteFileCreateSnapshot(BNRemoteFile* file, const char* name, uint8_t* contents, size_t contentsSize, uint8_t* analysisCacheContents, size_t analysisCacheContentsSize, uint8_t* fileContents, size_t fileContentsSize, const char** parentIds, size_t parentIdCount, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK bool BNRemoteFileDeleteSnapshot(BNRemoteFile* file, BNCollaborationSnapshot* snapshot) { return false; }
BN_WEAK bool BNRemoteFileDownload(BNRemoteFile* file, BNProgressFunction progress, void* progressCtxt) { return false; }
BN_WEAK bool BNRemoteFileDownloadContents(BNRemoteFile* file, BNProgressFunction progress, void* progressCtxt, uint8_t** data, size_t* size) { return false; }
BN_WEAK char* BNRemoteFileGetChatLogUrl(BNRemoteFile* file) { return NULL; }
BN_WEAK BNProjectFile* BNRemoteFileGetCoreFile(BNRemoteFile* file) { return NULL; }
BN_WEAK int64_t BNRemoteFileGetCreated(BNRemoteFile* file) { return 0; }
BN_WEAK char* BNRemoteFileGetCreatedBy(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetDescription(BNRemoteFile* file) { return NULL; }
BN_WEAK BNRemoteFolder* BNRemoteFileGetFolder(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetHash(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetId(BNRemoteFile* file) { return NULL; }
BN_WEAK int64_t BNRemoteFileGetLastModified(BNRemoteFile* file) { return 0; }
BN_WEAK int64_t BNRemoteFileGetLastSnapshot(BNRemoteFile* file) { return 0; }
BN_WEAK char* BNRemoteFileGetLastSnapshotBy(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetLastSnapshotName(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetMetadata(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetName(BNRemoteFile* file) { return NULL; }
BN_WEAK BNRemoteProject* BNRemoteFileGetProject(BNRemoteFile* file) { return NULL; }
BN_WEAK BNRemote* BNRemoteFileGetRemote(BNRemoteFile* file) { return NULL; }
BN_WEAK uint64_t BNRemoteFileGetSize(BNRemoteFile* file) { return 0; }
BN_WEAK BNCollaborationSnapshot* BNRemoteFileGetSnapshotById(BNRemoteFile* file, const char* id) { return NULL; }
BN_WEAK BNCollaborationSnapshot** BNRemoteFileGetSnapshots(BNRemoteFile* file, size_t* count) { return NULL; }
BN_WEAK BNRemoteFileType BNRemoteFileGetType(BNRemoteFile* file) { return (BNRemoteFileType)0; }
BN_WEAK char* BNRemoteFileGetUrl(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileGetUserPositionsUrl(BNRemoteFile* file) { return NULL; }
BN_WEAK bool BNRemoteFileHasPulledSnapshots(BNRemoteFile* file) { return false; }
BN_WEAK bool BNRemoteFilePullSnapshots(BNRemoteFile* file, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK char* BNRemoteFileRequestChatLog(BNRemoteFile* file) { return NULL; }
BN_WEAK char* BNRemoteFileRequestUserPositions(BNRemoteFile* file) { return NULL; }
BN_WEAK bool BNRemoteFileSetDescription(BNRemoteFile* file, const char* description) { return false; }
BN_WEAK bool BNRemoteFileSetFolder(BNRemoteFile* file, BNRemoteFolder* folder) { return false; }
BN_WEAK bool BNRemoteFileSetMetadata(BNRemoteFile* file, const char* metadata) { return false; }
BN_WEAK bool BNRemoteFileSetName(BNRemoteFile* file, const char* name) { return false; }
BN_WEAK BNRemoteFileSearchMatch* BNRemoteFindFiles(BNRemote* remote, const char* name, size_t* count) { return NULL; }
BN_WEAK BNProjectFolder* BNRemoteFolderGetCoreFolder(BNRemoteFolder* folder) { return NULL; }
BN_WEAK char* BNRemoteFolderGetDescription(BNRemoteFolder* folder) { return NULL; }
BN_WEAK char* BNRemoteFolderGetId(BNRemoteFolder* folder) { return NULL; }
BN_WEAK char* BNRemoteFolderGetName(BNRemoteFolder* folder) { return NULL; }
BN_WEAK bool BNRemoteFolderGetParent(BNRemoteFolder* folder, BNRemoteFolder** parent) { return false; }
BN_WEAK BNRemoteProject* BNRemoteFolderGetProject(BNRemoteFolder* folder) { return NULL; }
BN_WEAK BNRemote* BNRemoteFolderGetRemote(BNRemoteFolder* folder) { return NULL; }
BN_WEAK char* BNRemoteFolderGetUrl(BNRemoteFolder* folder) { return NULL; }
BN_WEAK char* BNRemoteGetAddress(BNRemote* remote) { return NULL; }
BN_WEAK bool BNRemoteGetAuthBackends(BNRemote* remote, char*** backendIds, char*** backendNames, size_t* count) { return false; }
BN_WEAK BNCollaborationUser* BNRemoteGetCurrentUser(BNRemote* remote) { return NULL; }
BN_WEAK BNCollaborationGroup* BNRemoteGetGroupById(BNRemote* remote, uint64_t id) { return NULL; }
BN_WEAK BNCollaborationGroup* BNRemoteGetGroupByName(BNRemote* remote, const char* name) { return NULL; }
BN_WEAK BNCollaborationGroup** BNRemoteGetGroups(BNRemote* remote, size_t* count) { return NULL; }
BN_WEAK char* BNRemoteGetName(BNRemote* remote) { return NULL; }
BN_WEAK BNRemoteProject* BNRemoteGetProjectById(BNRemote* remote, const char* id) { return NULL; }
BN_WEAK BNRemoteProject* BNRemoteGetProjectByName(BNRemote* remote, const char* name) { return NULL; }
BN_WEAK BNRemoteProject** BNRemoteGetProjects(BNRemote* remote, size_t* count) { return NULL; }
BN_WEAK char* BNRemoteGetServerBuildId(BNRemote* remote) { return NULL; }
#if BN_CURRENT_CORE_ABI_VERSION >= 165
BN_WEAK BNVersionInfo BNRemoteGetServerBuildVersion(BNRemote* remote) { BNVersionInfo v{}; return v; }
#else
BN_WEAK char* BNRemoteGetServerBuildVersion(BNRemote* remote) { return NULL; }
#endif
BN_WEAK int BNRemoteGetServerVersion(BNRemote* remote) { return 0; }
BN_WEAK char* BNRemoteGetToken(BNRemote* remote) { return NULL; }
BN_WEAK char* BNRemoteGetUniqueId(BNRemote* remote) { return NULL; }
BN_WEAK BNCollaborationUser* BNRemoteGetUserById(BNRemote* remote, const char* id) { return NULL; }
BN_WEAK BNCollaborationUser* BNRemoteGetUserByUsername(BNRemote* remote, const char* username) { return NULL; }
BN_WEAK char* BNRemoteGetUsername(BNRemote* remote) { return NULL; }
BN_WEAK BNCollaborationUser** BNRemoteGetUsers(BNRemote* remote, size_t* count) { return NULL; }
BN_WEAK bool BNRemoteHasLoadedMetadata(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteHasPulledGroups(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteHasPulledProjects(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteHasPulledUsers(BNRemote* remote) { return false; }
BN_WEAK BNRemoteProject* BNRemoteImportLocalProject(BNRemote* remote, BNProject* localProject, BNProgressFunction progress, void* progressCtxt) { return NULL; }
BN_WEAK bool BNRemoteIsAdmin(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteIsConnected(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteIsEnterprise(BNRemote* remote) { return false; }
BN_WEAK bool BNRemoteLoadMetadata(BNRemote* remote) { return false; }
#if BN_CURRENT_CORE_ABI_VERSION >= 165
BN_WEAK bool BNRemoteProjectCanUserAdmin(BNRemoteProject* project, BNCollaborationUser* user) { return false; }
BN_WEAK bool BNRemoteProjectCanUserEdit(BNRemoteProject* project, BNCollaborationUser* user) { return false; }
BN_WEAK bool BNRemoteProjectCanUserView(BNRemoteProject* project, BNCollaborationUser* user) { return false; }
#else
BN_WEAK bool BNRemoteProjectCanUserAdmin(BNRemoteProject* project, const char* username) { return false; }
BN_WEAK bool BNRemoteProjectCanUserEdit(BNRemoteProject* project, const char* username) { return false; }
BN_WEAK bool BNRemoteProjectCanUserView(BNRemoteProject* project, const char* username) { return false; }
#endif
BN_WEAK void BNRemoteProjectClose(BNRemoteProject* project) { (void)0; }
BN_WEAK BNRemoteFile* BNRemoteProjectCreateFile(BNRemoteProject* project, const char* filename, uint8_t* contents, size_t contentsSize, const char* name, const char* description, BNRemoteFolder* folder, BNRemoteFileType type, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK BNRemoteFolder* BNRemoteProjectCreateFolder(BNRemoteProject* project, const char* name, const char* description, BNRemoteFolder* parent, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK BNCollaborationPermission* BNRemoteProjectCreateGroupPermission(BNRemoteProject* project, int64_t groupId, BNCollaborationPermissionLevel level, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK BNCollaborationPermission* BNRemoteProjectCreateUserPermission(BNRemoteProject* project, const char* userId, BNCollaborationPermissionLevel level, BNProgressFunction progress, void* progressContext) { return NULL; }
BN_WEAK bool BNRemoteProjectDeleteFile(BNRemoteProject* project, BNRemoteFile* file) { return false; }
BN_WEAK bool BNRemoteProjectDeleteFolder(BNRemoteProject* project, BNRemoteFolder* folder) { return false; }
BN_WEAK bool BNRemoteProjectDeletePermission(BNRemoteProject* project, BNCollaborationPermission* permission) { return false; }
BN_WEAK BNProject* BNRemoteProjectGetCoreProject(BNRemoteProject* project) { return NULL; }
BN_WEAK int64_t BNRemoteProjectGetCreated(BNRemoteProject* project) { return 0; }
BN_WEAK char* BNRemoteProjectGetDescription(BNRemoteProject* project) { return NULL; }
BN_WEAK BNRemoteFile* BNRemoteProjectGetFileById(BNRemoteProject* project, const char* id) { return NULL; }
BN_WEAK BNRemoteFile* BNRemoteProjectGetFileByName(BNRemoteProject* project, const char* name) { return NULL; }
BN_WEAK BNRemoteFile** BNRemoteProjectGetFiles(BNRemoteProject* project, size_t* count) { return NULL; }
BN_WEAK BNRemoteFolder* BNRemoteProjectGetFolderById(BNRemoteProject* project, const char* id) { return NULL; }
BN_WEAK BNRemoteFolder** BNRemoteProjectGetFolders(BNRemoteProject* project, size_t* count) { return NULL; }
BN_WEAK BNCollaborationPermission** BNRemoteProjectGetGroupPermissions(BNRemoteProject* project, size_t* count) { return NULL; }
BN_WEAK char* BNRemoteProjectGetId(BNRemoteProject* project) { return NULL; }
BN_WEAK int64_t BNRemoteProjectGetLastModified(BNRemoteProject* project) { return 0; }
BN_WEAK char* BNRemoteProjectGetName(BNRemoteProject* project) { return NULL; }
BN_WEAK BNCollaborationPermission* BNRemoteProjectGetPermissionById(BNRemoteProject* project, const char* id) { return NULL; }
BN_WEAK uint64_t BNRemoteProjectGetReceivedFileCount(BNRemoteProject* project) { return 0; }
BN_WEAK uint64_t BNRemoteProjectGetReceivedFolderCount(BNRemoteProject* project) { return 0; }
BN_WEAK BNRemote* BNRemoteProjectGetRemote(BNRemoteProject* project) { return NULL; }
BN_WEAK char* BNRemoteProjectGetUrl(BNRemoteProject* project) { return NULL; }
BN_WEAK BNCollaborationPermission** BNRemoteProjectGetUserPermissions(BNRemoteProject* project, size_t* count) { return NULL; }
BN_WEAK bool BNRemoteProjectHasPulledFiles(BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteProjectHasPulledGroupPermissions(BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteProjectHasPulledUserPermissions(BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteProjectIsAdmin(BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteProjectIsOpen(BNRemoteProject* project) { return false; }
BN_WEAK bool BNRemoteProjectOpen(BNRemoteProject* project, BNProgressFunction progress, void* progressCtxt) { return false; }
BN_WEAK bool BNRemoteProjectPullFiles(BNRemoteProject* project, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemoteProjectPullFolders(BNRemoteProject* project, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemoteProjectPullGroupPermissions(BNRemoteProject* project, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemoteProjectPullUserPermissions(BNRemoteProject* project, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemoteProjectPushFile(BNRemoteProject* project, BNRemoteFile* file, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK bool BNRemoteProjectPushFolder(BNRemoteProject* project, BNRemoteFolder* folder, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK bool BNRemoteProjectPushPermission(BNRemoteProject* project, BNCollaborationPermission* permission, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK bool BNRemoteProjectSetDescription(BNRemoteProject* project, const char* description) { return false; }
BN_WEAK bool BNRemoteProjectSetName(BNRemoteProject* project, const char* name) { return false; }
BN_WEAK bool BNRemotePullGroups(BNRemote* remote, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemotePullProjects(BNRemote* remote, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemotePullUsers(BNRemote* remote, BNProgressFunction progress, void* progressContext) { return false; }
BN_WEAK bool BNRemotePushGroup(BNRemote* remote, BNCollaborationGroup* group, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK bool BNRemotePushProject(BNRemote* remote, BNRemoteProject* project, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK bool BNRemotePushUser(BNRemote* remote, BNCollaborationUser* user, const char** extraFieldKeys, const char** extraFieldValues, size_t extraFieldCount) { return false; }
BN_WEAK int BNRemoteRequest(BNRemote* remote, void* request, void* ret) { return 0; }
BN_WEAK char* BNRemoteRequestAuthenticationToken(BNRemote* remote, const char* username, const char* password) { return NULL; }
BN_WEAK bool BNRemoteSearchGroups(BNRemote* remote, const char* prefix, uint64_t** groupIds, char*** groupNames, size_t* count) { return false; }
BN_WEAK bool BNRemoteSearchUsers(BNRemote* remote, const char* prefix, char*** userIds, char*** usernames, size_t* count) { return false; }
BN_WEAK char* BNTypeArchiveMergeConflictGetBaseSnapshotId(BNTypeArchiveMergeConflict* conflict) { return NULL; }
BN_WEAK char* BNTypeArchiveMergeConflictGetFirstSnapshotId(BNTypeArchiveMergeConflict* conflict) { return NULL; }
BN_WEAK char* BNTypeArchiveMergeConflictGetSecondSnapshotId(BNTypeArchiveMergeConflict* conflict) { return NULL; }
BN_WEAK BNTypeArchive* BNTypeArchiveMergeConflictGetTypeArchive(BNTypeArchiveMergeConflict* conflict) { return NULL; }
BN_WEAK char* BNTypeArchiveMergeConflictGetTypeId(BNTypeArchiveMergeConflict* conflict) { return NULL; }
BN_WEAK bool BNTypeArchiveMergeConflictSuccess(BNTypeArchiveMergeConflict* conflict, const char* value) { return false; }
BN_WEAK void BNUnregisterEnterpriseServerNotification(BNEnterpriseServerCallbacks* notify) { (void)0; }
BN_WEAK bool BNUpdateEnterpriseServerLicense(uint64_t timeout) { return false; }

} // extern "C"
