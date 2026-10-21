using System.Security.Principal;
using System.Text.Json.Nodes;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace FacuSecX.Monitor;

internal static class HelloAgent
{
    internal static string KeyNameFor(string installId) => Guid.TryParseExact(installId, "N", out _) ? "FacuSecX.ServerSecurityMonitor." + installId : throw new IOException("Identificador de Windows Hello no válido.");
    internal static string KeyName => KeyNameFor(State.Value("InstallId"));
    internal static async Task VerifyOwner(IWin32Window? owner = null)
    {
        if (WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid")) throw new UnauthorizedAccessException("La instalación pertenece a otro usuario de Windows.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(100));
        using var consent = new HelloConsent<bool>("Verificar propietario — Windows Hello", async cancellation =>
        {
        using var foreground = new HelloForeground();
        var key = await KeyCredentialManager.OpenAsync(KeyName).AsTask(cancellation);
        if (key.Status != KeyCredentialStatus.Success) throw new IOException("No se encontró la clave del propietario. No se reemplazarán sus cuentas.");
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(64);
        var proof = await key.Credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge)).AsTask(cancellation);
        if (proof.Status != KeyCredentialStatus.Success) throw new IOException("Windows Hello no autorizó reanudar la instalación.");
        CryptographicBuffer.CopyToByteArray(proof.Result, out var signature);
        if (!HelloProof.Check(State.Value("OwnerPublicKey"), challenge, signature, State.Value("OwnerAlgorithm"))) throw new UnauthorizedAccessException("La firma no corresponde al propietario registrado.");
        return true;
        }, timeout.Token);
        await consent.Run(owner);
    }
    internal static async Task<(string PublicKey, string Algorithm)> Enroll(string installId, IWin32Window? owner = null)
    {
        if (!await KeyCredentialManager.IsSupportedAsync()) throw new IOException("Configurá Windows Hello en este usuario de Windows antes de instalar el panel.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(100));
        using var consent = new HelloConsent<(string PublicKey, string Algorithm)>("Registrar propietario — Windows Hello", async cancellation =>
        {
        using var foreground = new HelloForeground();
        var result = await KeyCredentialManager.RequestCreateAsync(KeyNameFor(installId), KeyCredentialCreationOption.FailIfExists).AsTask(cancellation);
        if (result.Status != KeyCredentialStatus.Success) throw new IOException("Windows Hello no autorizó el registro del propietario. No se modificaron las cuentas.");
        CryptographicBuffer.CopyToByteArray(result.Credential.RetrievePublicKey(Windows.Security.Cryptography.Core.CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo), out var publicKey);
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(64);
        var proof = await result.Credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge)).AsTask(cancellation);
        if (proof.Status != KeyCredentialStatus.Success) throw new IOException("Windows Hello no confirmó la nueva clave. No se modificaron las cuentas.");
        CryptographicBuffer.CopyToByteArray(proof.Result, out var signature);
        var encoded = Convert.ToBase64String(publicKey);
        // Windows releases/providers differ. Pin the algorithm actually proven during enrollment.
        var algorithm = HelloProof.Check(encoded, challenge, signature, "PS256") ? "PS256" : HelloProof.Check(encoded, challenge, signature, "RS256") ? "RS256" : throw new IOException("No se pudo comprobar la firma de Windows Hello. La instalación se mantuvo sin cambios.");
        return (encoded, algorithm);
        }, timeout.Token);
        return await consent.Run(owner);
    }
    internal static void Run(bool showPicker = false) => DesktopController.Run(showPicker);
}
