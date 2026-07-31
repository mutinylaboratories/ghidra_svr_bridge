#include "ui/ConnectDialog.h"
#include <binaryninjaapi.h>

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QVBoxLayout>

ConnectDialog::ConnectDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Connect to Ghidra Server");
    setMinimumWidth(360);

    m_host     = new QLineEdit(this);
    m_port     = new QLineEdit(this);
    m_user     = new QLineEdit(this);
    m_password = new QLineEdit(this);
    m_password->setEchoMode(QLineEdit::Password);

    auto* form = new QFormLayout;
    form->addRow("Host:",     m_host);
    form->addRow("Port:",     m_port);
    form->addRow("Username:", m_user);
    form->addRow("Password:", m_password);

    auto* buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]{
        saveSettings();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(buttons);

    loadSettings();
}

QString ConnectDialog::host()     const { return m_host->text().trimmed(); }
int     ConnectDialog::port()     const { return m_port->text().toInt();   }
QString ConnectDialog::user()     const { return m_user->text().trimmed(); }
QString ConnectDialog::password() const { return m_password->text();       }

void ConnectDialog::loadSettings() {
    auto s = BinaryNinja::Settings::Instance();
    m_host->setText(QString::fromStdString(s->Get<std::string>("ghidra.defaultHost")));
    m_port->setText(QString::number(s->Get<int64_t>("ghidra.defaultPort")));
    m_user->setText(QString::fromStdString(s->Get<std::string>("ghidra.defaultUser")));
}

void ConnectDialog::preload(const QString& host, int port, const QString& user) {
    if (!host.isEmpty()) m_host->setText(host);
    if (port > 0)        m_port->setText(QString::number(port));
    if (!user.isEmpty()) m_user->setText(user);
}

void ConnectDialog::saveSettings() {
    auto s = BinaryNinja::Settings::Instance();
    s->Set("ghidra.defaultHost", host().toStdString());
    s->Set("ghidra.defaultPort", static_cast<int64_t>(port()));
    s->Set("ghidra.defaultUser", user().toStdString());
    // Password is intentionally NOT persisted.
}
