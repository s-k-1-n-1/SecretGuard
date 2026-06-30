# SecretGuard 🛡️
Локальная CLI-утилита для шифрования конфигурационных файлов (`.env`) на базе .NET 8 (C#).

## Технологический стек
- **Платформа:** .NET 8 (С поддержкой Native AOT компиляции)
- **CLI фреймворк:** `System.CommandLine`
- **Криптография:** `System.Security.Cryptography.AesGcm` (AES-256-GCM)
- **Логирование:** `Serilog`

## План работы (День 1)
- [x] Инициализация Git-репозитория и структуры проекта.
- [x] Настройка правил контроля версий (`.gitignore`).
- [x] Создание архитектурного скелета CLI и подключение логгера.

## запуск 
$env:SECRETGUARD_MASTER_KEY="MySuperSecretPassword123_!!!_777"

"API_KEY=my_secret_key_123" | Out-File -FilePath .env -Encoding utf8
dotnet run --project C:\Users\student\Downloads\SecretGuard-main\SecretGuard\src\SecretGuard -- encrypt -i .env -o .env.enc

dotnet run --project C:\Users\student\Downloads\SecretGuard-main\SecretGuard\src\SecretGuard -- decrypt -i .env.enc -o .env.decrypted

