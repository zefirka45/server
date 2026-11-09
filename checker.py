#!/usr/bin/env  python3
import logging
import datetime
import json
from pathlib import Path
from typing import List, Sequence

from cryptography import x509

logger = logging.getLogger(__name__)


class CertificateFinder:
    def __init__(self,
        directory: str | Path,
        extensions: Sequence[str] = (".pem", ".crt", ".cer"),
    ) -> None:
        self.directory = Path(directory)
        self.extensions = tuple(
            ext if ext.startswith(".") else f".{ext}" for ext in extensions
        )

    def search(self) -> List[Path]:
        """Возвращает список путей к файлам с нужными расширениями."""
        if not self.directory.is_dir():
            raise NotADirectoryError(f"Директория не найдена: {self.directory}")

        found: List[Path] = []
        for ext in self.extensions:
            try:
                found.extend(self.directory.rglob(f"*{ext}"))
            except PermissionError as e:
                logger.warning("Нет прав доступа для поиска в %s: %s", self.directory, e)
            except OSError as e:
                logger.error("Ошибка файловой системы при поиске в %s: %s", self.directory, e)
                raise
                
        return sorted(found)

    def load_certificates(self) -> List[x509.Certificate]:
        """Загружает и парсит все найденные сертификаты."""
        certificates: List[x509.Certificate] = []
        for path in self.search():
            try:
                cert = x509.load_pem_x509_certificate(path.read_bytes())
                certificates.append(cert)
                logger.info("Загружен сертификат: %s", path)
            except ValueError as exc:
                logger.warning("Пропущен файл %s: не является PEM-сертификатом (%s)", path, exc)
            except OSError as exc:
                logger.error("Не удалось прочитать файл %s: %s", path, exc)
        return certificates
    
    def get_expired_certificates(self, threshold_days: int = 30):
        current_time = datetime.datetime.now()
        threshold_date = current_time + datetime.timedelta(days=threshold_days)
        expired: List[x509.Certificate] = []
        for cert in self.load_certificates():
          if cert.not_valid_after <= threshold_date:
                expired.append(cert)
        return expired
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Для теста берем конкретную папку, чтобы не сканировать весь диск
    finder = CertificateFinder("/etc/ssl/certs", extensions=(".crt", ".pem"))
    
    certs = finder.load_certificates()
    # Проверяем сертификаты, которые истекут в течение следующего года (365 дней)
    expired_certs = finder.get_expired_certificates(threshold_days=365)
    
    print(f"\nВсего загружено сертификатов: {len(certs)}")
    print(f"Истекают в течение года: {len(expired_certs)}")
    
    # Форматируем вывод
    if expired_certs:
        print("\n📋 Список проблемных сертификатов:")
        all_expired=[]
        for cert in expired_certs:
            subject = cert.subject.rfc4514_string()
            expiry_date = cert.not_valid_after.strftime("%Y-%m-%d")
            print(f" ! {subject.split(',',1)[0]} (истекает: {expiry_date})")
            data = {
                "CN":subject.split(',',1)[0], 
                "TIME":expiry_date 
            }
            all_expired.append(data)
            #Формируем json 
            with open("cert.json","w", encoding="utf-8") as f:
                json.dump(all_expired, f ,ensure_ascii=False, indent=4)
    else:
        print("\nВсе сертификаты в порядке!")
