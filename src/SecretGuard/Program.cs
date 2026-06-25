using System;
using System.IO;
using System.CommandLine;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using Serilog;
using Serilog.Events;

namespace SecretGuard
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Logger(lc => lc
                    .Filter.ByIncludingOnly(e => e.Level >= LogEventLevel.Error)
                    .WriteTo.File("logs/error.log", rollingInterval: Serilog.RollingInterval.Day))
                .WriteTo.Logger(lc => lc
                    .Filter.ByIncludingOnly(e => e.Level < LogEventLevel.Error)
                    .WriteTo.File("logs/info.log", rollingInterval: Serilog.RollingInterval.Day))
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            Log.Information("SecretGuard запущен в контейнеризированном окружении.");

            var rootCommand = new RootCommand("SecretGuard — утилита для защиты секретов разработки.");

            var inputOption = new Option<string>(new[] { "--input", "-i" }, "Путь к исходному файлу") { IsRequired = true };
            var outputOption = new Option<string>(new[] { "--output", "-o" }, "Путь к выходному зашифрованному файлу");

            var encryptCommand = new Command("encrypt", "Зашифровать файл с использованием AES-256-GCM") { inputOption, outputOption };
            var decryptCommand = new Command("decrypt", "Расшифровать защищенный файл обратно") { inputOption, outputOption };

            rootCommand.AddCommand(encryptCommand);
            rootCommand.AddCommand(decryptCommand);

            encryptCommand.SetHandler((string input, string output) =>
            {
                output ??= input + ".enc";
                Log.Information("Старт шифрования файла: {Input} -> {Output}", input, output);

                if (!File.Exists(input))
                {
                    Log.Error("Критическая ошибка: Файл {Input} не найден!", input);
                    return;
                }

                try
                {
                    string masterKey = Environment.GetEnvironmentVariable("SECRETGUARD_MASTER_KEY") ?? "FallbackDefaultKey32BytesLong12345!";
                    byte[] key = Encoding.UTF8.GetBytes(masterKey.PadRight(32).Substring(0, 32));
                    byte[] secretData = File.ReadAllBytes(input);

                    byte[] nonce = new byte[12];
                    byte[] tag = new byte[16];
                    byte[] ciphertext = new byte[secretData.Length];
                    
                    RandomNumberGenerator.Fill(nonce);

                    using (var aesGcm = new AesGcm(key, tag.Length))
                    {
                        aesGcm.Encrypt(nonce, secretData, ciphertext, tag);
                    }

                    using (var fs = File.Create(output))
                    using (var bw = new BinaryWriter(fs))
                    {
                        bw.Write(nonce.Length);
                        bw.Write(nonce);
                        bw.Write(tag.Length);
                        bw.Write(tag);
                        bw.Write(ciphertext.Length);
                        bw.Write(ciphertext);
                    }

                    Log.Information("Файл успешно защищен и сохранен в {Output}", output);
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "Критический сбой при выполнении шифрования.");
                }
            }, inputOption, outputOption);

            decryptCommand.SetHandler((string input, string output) =>
            {
                output ??= input.Replace(".enc", ".dec");
                Log.Information("Старт дешифрации файла: {Input}", input);

                if (!File.Exists(input))
                {
                    Log.Error("Критическая ошибка: Зашифрованный файл {Input} не найден!", input);
                    return;
                }

                try
                {
                    string masterKey = Environment.GetEnvironmentVariable("SECRETGUARD_MASTER_KEY") ?? "FallbackDefaultKey32BytesLong12345!";
                    byte[] key = Encoding.UTF8.GetBytes(masterKey.PadRight(32).Substring(0, 32));

                    byte[] nonce, tag, ciphertext;
                    using (var fs = File.OpenRead(input))
                    using (var br = new BinaryReader(fs))
                    {
                        int nonceLen = br.ReadInt32();
                        nonce = br.ReadBytes(nonceLen);
                        int tagLen = br.ReadInt32();
                        tag = br.ReadBytes(tagLen);
                        int cipherLen = br.ReadInt32();
                        ciphertext = br.ReadBytes(cipherLen);
                    }

                    byte[] decryptedData = new byte[ciphertext.Length];

                    using (var aesGcm = new AesGcm(key, tag.Length))
                    {
                        aesGcm.Decrypt(nonce, ciphertext, tag, decryptedData);
                    }

                    File.WriteAllBytes(output, decryptedData);
                    Log.Information("Файл успешно расшифрован: {Output}", output);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Ошибка расшифровки. Возможно, указан неверный мастер-ключ.");
                }
            }, inputOption, outputOption);

            try
            {
                return await rootCommand.InvokeAsync(args);
            }
            finally
            {
                await Log.CloseAndFlushAsync();
            }
        }
    }
}