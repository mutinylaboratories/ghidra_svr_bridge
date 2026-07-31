package com.ghidra_svr.bridge;

import ghidra.framework.remote.*;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

import javax.net.ssl.SSLHandshakeException;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages a single authenticated connection to a Ghidra Server.
 *
 * All public methods are safe to call from the connection-handler thread.
 * The open-repo map is a ConcurrentHashMap so EventStreamer threads can read
 * it without holding the session lock.
 */
public class GhidraSession {

    private RemoteRepositoryServerHandle serverHandle;
    private final Map<String, RepositoryHandle> openRepos = new ConcurrentHashMap<>();
    private String connectedUser;

    // -------------------------------------------------------------------------
    // Connection lifecycle
    // -------------------------------------------------------------------------

    public synchronized void connect(String host, int port, String user, String password)
            throws Exception {
        disconnect();

        try {
            // Ghidra 9.1+ wraps the RMI registry itself in SSL.
            Registry registry = LocateRegistry.getRegistry(host, port, new SslRMIClientSocketFactory());

            GhidraServerHandle handle =
                    (GhidraServerHandle) registry.lookup(GhidraServerHandle.BIND_NAME);
            handle.checkCompatibility(GhidraServerHandle.INTERFACE_VERSION);

            Callback[] callbacks = handle.getAuthenticationCallbacks();
            if (callbacks != null) {
                satisfyCallbacks(callbacks, user, password);
            }

            Subject subject = new Subject();
            subject.getPrincipals().add(new GhidraPrincipal(user));
            subject.setReadOnly();

            serverHandle = handle.getRepositoryServer(subject, callbacks);
            // Signal to the server that the client has fully connected.
            serverHandle.connected();
            connectedUser = user;

        } catch (SSLHandshakeException e) {
            throw new Exception(classifySSLError(e), e);
        } catch (java.rmi.RemoteException e) {
            // RemoteException wraps the SSL failure when it occurs during the RMI call itself.
            Throwable cause = e.getCause();
            if (cause instanceof SSLHandshakeException) {
                throw new Exception(classifySSLError((SSLHandshakeException) cause), e);
            }
            throw e;
        }
    }

    /**
     * Returns a human-readable message for SSL handshake failures, with a hint
     * pointing to the Binary Ninja setting that disables certificate validation.
     */
    private static String classifySSLError(SSLHandshakeException e) {
        String msg = e.getMessage() != null ? e.getMessage() : "";
        String cause = e.getCause() != null ? e.getCause().getMessage() : "";
        String combined = msg + " " + cause;

        if (combined.contains("PKIX") || combined.contains("unable to find valid certification path")
                || combined.contains("certificate_unknown")) {
            return "SSL certificate not trusted — the Ghidra Server is likely using a self-signed "
                    + "certificate. Enable 'Trust All Certs' in Binary Ninja settings "
                    + "(Preferences → Settings → search 'Ghidra' → ghidra.trustAllCerts) "
                    + "and restart Binary Ninja.";
        }
        if (combined.contains("No subject alternative") || combined.contains("hostname")) {
            return "SSL hostname mismatch — the server certificate was not issued for '"
                    + "the hostname you connected to. Enable 'Trust All Certs' in Binary Ninja "
                    + "settings (Preferences → Settings → search 'Ghidra' → ghidra.trustAllCerts) "
                    + "and restart Binary Ninja, or regenerate the server certificate with the "
                    + "correct hostname.";
        }
        return "SSL handshake failed: " + msg;
    }

    public synchronized void disconnect() {
        for (RepositoryHandle repo : openRepos.values()) {
            try { repo.close(); } catch (Exception ignored) {}
        }
        openRepos.clear();
        serverHandle = null;
        connectedUser = null;
    }

    // -------------------------------------------------------------------------
    // Repository operations
    // -------------------------------------------------------------------------

    public String[] listRepos() throws Exception {
        requireConnected();
        return serverHandle.getRepositoryNames();
    }

    public void openRepo(String name) throws Exception {
        requireConnected();
        if (openRepos.containsKey(name)) return;
        RepositoryHandle repo = serverHandle.getRepository(name);
        if (repo == null) throw new Exception("Repository not found: " + name);
        openRepos.put(name, repo);
    }

    public void closeRepo(String name) throws Exception {
        RepositoryHandle repo = openRepos.remove(name);
        if (repo != null) {
            try { repo.close(); } catch (Exception ignored) {}
        }
    }

    /** Package-private so EventStreamer can hold the handle directly. */
    RepositoryHandle getRepo(String name) throws Exception {
        RepositoryHandle repo = openRepos.get(name);
        if (repo == null) throw new Exception("Repository not open: " + name);
        return repo;
    }

    // -------------------------------------------------------------------------
    // Folder / item listing
    // -------------------------------------------------------------------------

    public String[] getSubfolders(String repoName, String folderPath) throws Exception {
        return getRepo(repoName).getSubfolderList(folderPath);
    }

    public RepositoryItem[] listItems(String repoName, String folderPath) throws Exception {
        return getRepo(repoName).getItemList(folderPath);
    }

    // -------------------------------------------------------------------------
    // Version control
    // -------------------------------------------------------------------------

    public ItemCheckoutStatus checkout(String repoName, String parentPath, String itemName,
            String checkoutTypeName, String projectPath) throws Exception {
        CheckoutType type = CheckoutType.valueOf(checkoutTypeName.toUpperCase());
        return getRepo(repoName).checkout(parentPath, itemName, type, projectPath);
    }

    public void terminateCheckout(String repoName, String parentPath, String itemName,
            long checkoutId) throws Exception {
        // notify=true so other clients receive a change event.
        getRepo(repoName).terminateCheckout(parentPath, itemName, checkoutId, true);
    }

    public Version[] getVersions(String repoName, String parentPath, String itemName)
            throws Exception {
        return getRepo(repoName).getVersions(parentPath, itemName);
    }

    public ItemCheckoutStatus[] getCheckouts(String repoName, String parentPath, String itemName)
            throws Exception {
        return getRepo(repoName).getCheckouts(parentPath, itemName);
    }

    // -------------------------------------------------------------------------
    // State accessors
    // -------------------------------------------------------------------------

    public String getConnectedUser() { return connectedUser; }
    public boolean isConnected()     { return serverHandle != null; }
    /** Package seam for the live-server E2E tests — the raw server handle. */
    RemoteRepositoryServerHandle serverHandle() { return serverHandle; }
    public Set<String> getOpenRepos(){ return Collections.unmodifiableSet(openRepos.keySet()); }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void requireConnected() {
        if (serverHandle == null) throw new IllegalStateException("Not connected to Ghidra server");
    }

    private static void satisfyCallbacks(Callback[] callbacks, String user, String password)
            throws UnsupportedCallbackException {
        for (Callback cb : callbacks) {
            if (cb instanceof NameCallback) {
                ((NameCallback) cb).setName(user);
            } else if (cb instanceof PasswordCallback) {
                // Password is transmitted plaintext over the TLS-encrypted RMI channel;
                // the server hashes it server-side for comparison with its stored hash.
                ((PasswordCallback) cb).setPassword(password.toCharArray());
            } else if (cb instanceof AnonymousCallback) {
                // Server permits anonymous access, but we have credentials — opt out.
                ((AnonymousCallback) cb).setAnonymousAccessRequested(false);
            } else {
                // TODO: add PKI/SSH key support (SignatureCallback / SSHSignatureCallback)
                throw new UnsupportedCallbackException(cb,
                    "Unsupported auth callback: " + cb.getClass().getSimpleName() +
                    ". Only password authentication is currently implemented.");
            }
        }
    }
}
