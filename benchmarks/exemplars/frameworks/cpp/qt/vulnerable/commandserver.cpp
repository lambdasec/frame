// A Qt TCP admin service: each line is "VERB argument".
#include <QCoreApplication>
#include <QFile>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QProcess>
#include <QSqlQuery>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>

class CommandServer : public QTcpServer {
    Q_OBJECT
public slots:
    void onReadyRead();
};

void CommandServer::onReadyRead() {
    QTcpSocket *sock = qobject_cast<QTcpSocket *>(sender());
    if (!sock)
        return;
    QString line = QString::fromUtf8(sock->readLine()).trimmed();
    QString verb = line.section(' ', 0, 0);
    QString arg = line.section(' ', 1);

    if (verb == "PING") {
        QProcess proc;
        proc.start("sh", QStringList() << "-c" << "ping -c 1 " + arg); /* frame-expect: CWE-78 */
        proc.waitForFinished();
        sock->write(proc.readAllStandardOutput());
    } else if (verb == "USER") {
        QSqlQuery query;
        query.exec("SELECT email FROM users WHERE name = '" + arg + "'"); /* frame-expect: CWE-89 */
        if (query.next())
            sock->write(query.value(0).toString().toUtf8());
    } else if (verb == "CAT") {
        QFile file("/srv/data/" + arg); /* frame-expect: CWE-22 */
        if (file.open(QIODevice::ReadOnly))
            sock->write(file.readAll());
    } else if (verb == "FETCH") {
        QNetworkAccessManager manager;
        QUrl target(arg);
        QNetworkRequest request(target);
        manager.get(request); /* frame-expect: CWE-918 */
    }
}
