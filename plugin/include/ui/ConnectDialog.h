#pragma once
#include <QDialog>
#include <QString>

class QLineEdit;
class QCheckBox;
class QDialogButtonBox;

/**
 * Modal dialog for entering Ghidra server credentials.
 *
 * Pre-populates from BN Settings (binja-ghidra.*) and saves back on accept.
 */
class ConnectDialog : public QDialog {
    Q_OBJECT
public:
    explicit ConnectDialog(QWidget* parent = nullptr);

    QString host()     const;
    int     port()     const;
    QString user()     const;
    QString password() const;

    /** Override the BN-settings defaults (e.g. from .bndb Ghidra link metadata). */
    void preload(const QString& host, int port, const QString& user);

private:
    QLineEdit* m_host;
    QLineEdit* m_port;
    QLineEdit* m_user;
    QLineEdit* m_password;

    void saveSettings();
    void loadSettings();
};
