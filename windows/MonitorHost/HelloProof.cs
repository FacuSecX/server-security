using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal sealed class HelloProof
{
    private readonly Func<string> installId;
    private readonly Func<string> ownerPublicKey;
    private readonly Func<string> ownerAlgorithm;
    internal HelloProof(Func<string>? installId = null, Func<string>? ownerPublicKey = null, Func<string>? ownerAlgorithm = null) { this.installId = installId ?? (() => State.Value("InstallId")); this.ownerPublicKey = ownerPublicKey ?? (() => State.Value("OwnerPublicKey")); this.ownerAlgorithm = ownerAlgorithm ?? (ownerPublicKey != null ? () => "PS256" : () => State.Value("OwnerAlgorithm")); }
    private readonly object sync = new();
    private Pending? pending;
    private DateTime permitUntil;
    private string permitPurpose = "";
    internal sealed record Pending(string Id, string Purpose, byte[] Message, DateTime Expires, TaskCompletionSource<bool> Completion);
    internal async Task<bool> Verify(string purpose, CancellationToken cancellation)
    {
        if (purpose is not ("terminal" or "users" or "setup" or "recovery" or "game-ftp")) throw new InvalidOperationException("Propósito de verificación no válido.");
        Pending item;
        lock (sync)
        {
            if (pending != null) throw new IOException("Ya hay una verificación de Windows Hello en curso.");
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var id = Guid.NewGuid().ToString("N");
            var message = Encoding.UTF8.GetBytes("FacuSecX/HelloProof/v2\n" + installId() + "\n" + purpose + "\n" + id + "\n" + nonce);
            item = new Pending(id, purpose, message, DateTime.UtcNow.AddSeconds(90), new(TaskCreationOptions.RunContinuationsAsynchronously)); pending = item;
        }
        try
        {
            var success = await item.Completion.Task.WaitAsync(TimeSpan.FromSeconds(90), cancellation);
            if (success && purpose is "setup" or "recovery" or "game-ftp") lock (sync) { permitPurpose = purpose; permitUntil = DateTime.UtcNow.AddSeconds(15); }
            return success;
        }
        finally { lock (sync) { if (pending == item) pending = null; } }
    }
    internal JsonObject Poll()
    {
        lock (sync)
        {
            if (pending == null || pending.Expires <= DateTime.UtcNow) return new() { ["pending"] = false };
            return new() { ["pending"] = true, ["id"] = pending.Id, ["purpose"] = pending.Purpose, ["message"] = Convert.ToBase64String(pending.Message) };
        }
    }
    internal bool Reply(string id, string signature)
    {
        lock (sync)
        {
            var item = pending;
            if (item == null || item.Id != id || item.Expires <= DateTime.UtcNow || item.Completion.Task.IsCompleted) return false;
            bool valid = false;
            try { valid = Check(ownerPublicKey(), item.Message, Convert.FromBase64String(signature), ownerAlgorithm()); } catch { }
            // Consume both valid and invalid responses. No signature retry or replay.
            item.Completion.TrySetResult(valid); return valid;
        }
    }
    internal void ConsumePermit(string purpose)
    {
        lock (sync)
        {
            var valid = permitPurpose == purpose && DateTime.UtcNow < permitUntil;
            permitPurpose = ""; permitUntil = DateTime.MinValue;
            if (!valid) throw new UnauthorizedAccessException("Confirmá esta operación con Windows Hello.");
        }
    }
    internal static bool Check(string publicKey, byte[] message, byte[] signature, string algorithm = "PS256")
    {
        using var rsa = RSA.Create(); rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out var count);
        if (algorithm is not ("PS256" or "RS256")) return false;
        return count == Convert.FromBase64String(publicKey).Length && rsa.KeySize >= 2048 && rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, algorithm == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
    }
}
