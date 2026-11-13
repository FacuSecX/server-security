using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class ServerProfileRemovalTests
{
    internal static async Task<int> Run()
    {
        int passed = 0; void Check(bool value) { if (!value) throw new IOException("Falló la eliminación de conexiones guardadas."); passed++; }
        string a = new('a', 32), b = new('b', 32);
        JsonObject Profile(string id) => new() { ["id"] = id, ["label"] = "synthetic.example", ["legacy"] = false,
            ["settings"] = new JsonObject { ["host"] = "synthetic.example", ["port"] = 22, ["user"] = "test", ["mode"] = "password", ["secret"] = "synthetic-only", ["fingerprint"] = "SHA256:" + new string('A', 43) } };
        JsonObject? store = null; var steps = new List<string>(); bool running = true, busy = false, closed = false, rejectWrite = false;
        var profiles = new ServerProfiles(() => store?.DeepClone().AsObject(), value => { steps.Add("save"); if (rejectWrite) throw new IOException("synthetic write failure"); store = value.DeepClone().AsObject(); });
        profiles.Save(profiles.WithActive(Profile(a))); profiles.Save(profiles.WithActive(Profile(b)));
        var lifecycle = new RuntimeLifecycle(() => running, _ => { steps.Add("suspend"); if (busy) throw new IOException("synthetic busy"); return Task.CompletedTask; },
            () => { steps.Add("stop"); running = false; }, _ => { steps.Add("reset"); return Task.CompletedTask; }, () => { steps.Add("closed"); closed = true; });
        var removal = new ServerProfileRemoval(profiles, lifecycle.Disconnect);
        steps.Clear(); await removal.Remove(a, CancellationToken.None);
        Check(steps.SequenceEqual(new[] { "save" }) && running && !closed);
        Check(profiles.Active()!["id"]!.GetValue<string>() == b && profiles.Listing()["profiles"]!.AsArray().Count == 1);
        profiles.Save(profiles.WithActive(Profile(a))); profiles.Save(profiles.WithActive(Profile(b)));
        var prior = store!.DeepClone(); steps.Clear(); busy = true;
        try { await removal.Remove(b, CancellationToken.None); Check(false); } catch (IOException) { Check(JsonNode.DeepEquals(prior, store) && running && !closed && steps.SequenceEqual(new[] { "suspend" })); }
        busy = false; steps.Clear(); await removal.Remove(b, CancellationToken.None);
        Check(steps.SequenceEqual(new[] { "suspend", "closed", "stop", "reset", "save" }) && !running && closed);
        Check(profiles.Active() == null && profiles.Listing()["active"]!.GetValue<string>() == "");
        Check(profiles.Get(a)["id"]!.GetValue<string>() == a);
        profiles.Save(profiles.WithActive(Profile(b))); running = true; closed = false; steps.Clear(); prior = store.DeepClone(); rejectWrite = true;
        try { await removal.Remove(b, CancellationToken.None); Check(false); } catch (IOException) { Check(JsonNode.DeepEquals(prior, store) && !running && closed); }
        Check(steps.SequenceEqual(new[] { "suspend", "closed", "stop", "reset", "save" }));
        rejectWrite = false; steps.Clear(); prior = store.DeepClone();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        try { await removal.Remove(b, canceled.Token); Check(false); } catch (OperationCanceledException) { Check(steps.Count == 0 && JsonNode.DeepEquals(prior, store)); }
        foreach (var invalid in new[] { "", "../outside", new string('a', 32) + "\n", new string('c', 32) }) {
            steps.Clear(); try { await removal.Remove(invalid, CancellationToken.None); Check(false); } catch (IOException) { Check(steps.Count == 0 && JsonNode.DeepEquals(prior, store)); }
        }
        foreach (string op in new[] { "servers-list", "server-prepare", "server-commit", "server-remove" }) Check(Broker.IsProfileOperation(op));
        foreach (string op in new[] { "server-remove-other", "ssh", "runtime-close", "vault-save" }) Check(!Broker.IsProfileOperation(op));
        Check(Broker.IsServerRequestAllowed(false, a, a));
        Check(!Broker.IsServerRequestAllowed(false, null, null)); Check(!Broker.IsServerRequestAllowed(false, "", ""));
        Check(!Broker.IsServerRequestAllowed(false, a, b)); Check(!Broker.IsServerRequestAllowed(true, a, a));
        return passed;
    }
}
