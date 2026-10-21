using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class PasswordVerifier
{
    internal static async Task<JsonObject> Verify(JsonObject accounts, string password, string node, string script, int? port = null)
    {
        using var validator = new Process { StartInfo = new ProcessStartInfo(node) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false), WorkingDirectory = Path.GetDirectoryName(script)!
        } };
        validator.StartInfo.Environment.Remove("NODE_OPTIONS");
        validator.StartInfo.Environment.Remove("NODE_PATH");
        validator.StartInfo.ArgumentList.Add(script);
        validator.Start();
        var error = validator.StandardError.BaseStream.CopyToAsync(Stream.Null);
        var output = validator.StandardOutput.ReadToEndAsync();
        using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            await validator.StandardInput.WriteAsync(new JsonObject { ["accounts"] = accounts.DeepClone(), ["password"] = password, ["port"] = port }.ToJsonString().AsMemory(), wait.Token);
            validator.StandardInput.Close();
            await validator.WaitForExitAsync(wait.Token);
            await Task.WhenAll(error, output).WaitAsync(wait.Token);
        }
        catch
        {
            try { if (!validator.HasExited) validator.Kill(true); } catch { }
            throw new IOException("No respondió la comprobación local de cuentas. Tus cuentas no se modificaron; volvé a intentarlo.");
        }
        if (validator.ExitCode == 0) {
            var response = await output;
            if (response.Length > 1_100_000) throw new IOException("Respuesta de verificación no válida.");
            return JsonNode.Parse(response)?.AsObject() ?? throw new IOException("Respuesta de verificación vacía.");
        }
        throw new IOException(validator.ExitCode switch {
            2 => "La contraseña ingresada no coincide con la del administrador principal del panel. Podés usar Mostrar para comprobar lo escrito. La frase de la PPK va en el segundo campo. Tus cuentas no se modificaron.",
            3 => "El asistente no pudo validar el formato de las cuentas existentes. Tus cuentas no se modificaron; no es un error de contraseña.",
            4 => "Falló la lectura de la comprobación local. Tus cuentas no se modificaron; no es un error de contraseña.",
            6 => "La contraseña es válida en el panel abierto, pero sus cuentas no coinciden con la copia local. La migración se detuvo para conservar todas las cuentas y permisos.",
            _ => "No se pudo ejecutar el verificador local de cuentas. Tus cuentas no se modificaron; no es un error de contraseña."
        });
    }
}
