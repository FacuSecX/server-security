using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

// The caller holds serversLock. Only the encrypted profile index is written;
// server data directories, accounts and the remote server are never modified.
internal sealed class ServerProfileRemoval(ServerProfiles profiles, Func<CancellationToken, Task> disconnect)
{
    internal async Task<JsonObject> Remove(string id, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var current = profiles.Load();
        var replacement = profiles.Without(id);
        if (current["active"]!.GetValue<string>() == id) await disconnect(token);
        profiles.Save(replacement);
        return profiles.Listing();
    }
}
