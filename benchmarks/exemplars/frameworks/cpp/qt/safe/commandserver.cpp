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
        // only hosts from our inventory may be pinged; the argument list is built from constants
        static const QStringList inventory = {"db.internal", "cache.internal"};
        for (const QString &known : inventory) {
            if (arg == known)
                proc.start("ping", QStringList() << "-c" << "1" << known);
        }
        proc.waitForFinished();
        sock->write(proc.readAllStandardOutput());
    } else if (verb == "USER") {
        QSqlQuery query;
        query.prepare("SELECT email FROM users WHERE name = ?");
        query.addBindValue(arg);
        query.exec();
        if (query.next())
            sock->write(query.value(0).toString().toUtf8());
    } else if (verb == "CAT") {
        static const QStringList exports = {"stock.csv", "orders.csv"};
        for (const QString &known : exports) {
            if (arg != known)
                continue;
            QFile file("/srv/data/" + known);
            if (file.open(QIODevice::ReadOnly))
                sock->write(file.readAll());
        }
    } else if (verb == "FETCH") {
        QNetworkAccessManager manager;
        QUrl target("https://status.example.com/api/" + QString::number(arg.toInt()));
        QNetworkRequest request(target);
        manager.get(request);
    }
}
