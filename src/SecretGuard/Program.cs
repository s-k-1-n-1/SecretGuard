using System;
using System.CommandLine;
using System.Threading.Tasks;
using Serilog;

namespace SecretGuard
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            Log.Information("SecretGuard CLI инициализирован успешно.");

            var rootCommand = new RootCommand("SecretGuard — CLI-утилита для безопасного управления секретами.");

            
            var inputOption = new Option<string>(new[] { "--input", "-i" }, "Путь к исходному файлу") { IsRequired = true };
            var outputOption = new Option<string>(new[] { "--output", "-o" }, "Путь к выходному файлу");
            var commandOption = new Option<string>(new[] { "--command", "-c" }, "Команда для выполнения в безопасном окружении");

         
            var encryptCommand = new Command("encrypt", "Зашифровать файл конфигурации (например, .env)") { inputOption, outputOption };
            var decryptCommand = new Command("decrypt", "Расшифровать защищенный файл обратно") { inputOption, outputOption };
            var runCommand = new Command("run", "Запустить приложение с внедрением секретов в память") { inputOption, commandOption };

            rootCommand.AddCommand(encryptCommand);
            rootCommand.AddCommand(decryptCommand);
            rootCommand.AddCommand(runCommand);

           
            encryptCommand.SetHandler((string input, string output) => {
                Log.Information("Вызвана команда шифрования для файла: {Input}", input);
            }, inputOption, outputOption);

            decryptCommand.SetHandler((string input, string output) => {
                Log.Information("Вызвана команда расшифровки файла: {Input}", input);
            }, inputOption, outputOption);

            runCommand.SetHandler((string input, string cmd) => {
                Log.Information("Вызов безопасного запуска команды '{Cmd}' с использованием файла {Input}", cmd, input);
            }, inputOption, commandOption);

            try
            {
                return await rootCommand.InvokeAsync(args);
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Произошла критическая ошибка.");
                return 1;
            }
            finally
            {
                await Log.CloseAndFlushAsync();
            }
        }
    }
}