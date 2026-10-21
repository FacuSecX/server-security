using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class NativeTests
{
    internal static async Task Run()
    {
        int passed = 0;
        passed += HelloConsentTests.Run();
        passed += HelloForegroundTests.Run();
        passed += RegistryPermissionTests.Run();
        passed += ServerProfileTests.Run();
        passed += GameFtpScopeTests.Run();
        void Check(bool valid) { if (!valid) throw new IOException("Native protection test failed."); passed++; }
        var ftpSecret = new JsonObject { ["scope"] = new string('a',64), ["id"] = new string('b',32), ["username"] = "sampftp", ["password"] = new string('c',32) };
        GameFtpSecrets.Validate(ftpSecret); passed++;
        foreach (var field in new[] { "scope", "id", "username", "password" })
        {
            var invalid = ftpSecret.DeepClone().AsObject(); invalid[field] = "../injected\n";
            try { GameFtpSecrets.Validate(invalid); Check(false); } catch (IOException) { passed++; }
        }
        Check(GameFtpSecrets.ScopeFor("host",22,"user","pin") != GameFtpSecrets.ScopeFor("host",22,"user","changed"));
        Check(GameFtpSecrets.ScopeFor("host",22,"user","pin") != GameFtpSecrets.ScopeFor("other",22,"user","pin"));
        Check(SshSettings.Host(" EXAMPLE.com ") == "example.com");
        Check(SshSettings.Host("2001:db8::1") == "2001:db8::1");
        foreach (var host in new[] { "", "https://example.com", "user@example.com", "example.com;id", "$(id)", "example.com\nother" })
            try { SshSettings.Host(host); Check(false); } catch (IOException) { passed++; }
        var ssh = SshSettings.Create("127.0.0.1", 22, "test", "password", " synthetic passphrase ", "SHA256:" + new string('A', 43), "", ".");
        Check(ssh["mode"]!.GetValue<string>() == "password" && ssh["secret"]!.GetValue<string>() == " synthetic passphrase " && ssh["privateKey"] == null);
        foreach (var args in new[] { new[] { "password", "", "test" }, new[] { "invalid", "secret", "test" }, new[] { "password", "secret", "root;id" }, new[] { "password", "secret\n", "test" } })
            try { SshSettings.Create("127.0.0.1", 22, args[2], args[0], args[1], "", "", "."); Check(false); } catch (IOException) { passed++; }
        var health = new JsonObject { ["app"] = "storypulse-security", ["protected_runtime"] = true, ["installation_ready"] = true, ["installation_id"] = "owner", ["installation_revision"] = "revision", ["installation_mode"] = "setup" };
        Check(SetupTransaction.Healthy(health, "owner", "revision"));
        Check(!SetupTransaction.Healthy(health, "other", "revision"));
        Check(!SetupTransaction.Healthy(health, "owner", "changed"));
        foreach (var property in new[] { "app", "protected_runtime", "installation_ready", "installation_id", "installation_revision", "installation_mode" })
        { var bad = health.DeepClone().AsObject(); bad.Remove(property); Check(!SetupTransaction.Healthy(bad, "owner", "revision")); }
        health["installation_mode"] = "recovery"; Check(!SetupTransaction.Healthy(health, "owner", "revision"));
        Check(HelloAgent.KeyNameFor(new string('a',32)) == "FacuSecX.ServerSecurityMonitor." + new string('a',32));
        try { HelloAgent.KeyNameFor("../invalid"); Check(false); } catch (IOException) { passed++; }
        var accounts = new JsonObject { ["version"] = 1, ["users"] = new JsonArray(new JsonObject { ["id"] = "primary-admin", ["username"] = "owner", ["primary"] = true, ["must_change"] = false, ["salt"] = new string('a', 32), ["hash"] = new string('b', 64) }) };
        var snapshot = new JsonObject { ["revision"] = 1L, ["accounts"] = accounts.DeepClone() };
        Check(State.Evaluate(false, null, null) == "setup");
        Check(State.Evaluate(true, snapshot, snapshot) == "ready");
        Check(State.Evaluate(true, null, snapshot) == "recovery");
        Check(State.Evaluate(true, snapshot, null) == "recovery");
        Check(State.Evaluate(true, null, null) == "recovery");
        Check(State.Evaluate(false, snapshot, snapshot) == "recovery");
        var changed = snapshot.DeepClone().AsObject(); changed["revision"] = 2L;
        Check(State.Evaluate(true, changed, snapshot) == "recovery");
        changed = snapshot.DeepClone().AsObject(); changed["accounts"]!["users"]![0]!["hash"] = new string('c', 64);
        Check(State.Evaluate(true, changed, snapshot) == "recovery");
        Check(State.Evaluate(true, new JsonObject(), snapshot) == "recovery");
        using var rsa = RSA.Create(2048); using var attacker = RSA.Create(2048);
        var publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()); var proof = new HelloProof(() => "test-installation", () => publicKey);
        var pkcsMessage = RandomNumberGenerator.GetBytes(32); var pkcsSignature = rsa.SignData(pkcsMessage, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Check(HelloProof.Check(publicKey, pkcsMessage, pkcsSignature, "RS256"));
        Check(!HelloProof.Check(publicKey, pkcsMessage, pkcsSignature, "PS256"));
        Check(!HelloProof.Check(publicKey, pkcsMessage, pkcsSignature, "none"));
        var task = proof.Verify("setup", CancellationToken.None); var challenge = proof.Poll();
        var message = Convert.FromBase64String(challenge["message"]!.GetValue<string>());
        var signature = Convert.ToBase64String(rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Check(!proof.Reply("wrong-id", signature)); Check(proof.Reply(challenge["id"]!.GetValue<string>(), signature)); Check(await task);
        Check(!proof.Reply(challenge["id"]!.GetValue<string>(), signature)); proof.ConsumePermit("setup");
        try { proof.ConsumePermit("setup"); Check(false); } catch (UnauthorizedAccessException) { passed++; }
        task = proof.Verify("recovery", CancellationToken.None); challenge = proof.Poll();
        var badSignature = Convert.ToBase64String(attacker.SignData(Convert.FromBase64String(challenge["message"]!.GetValue<string>()), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Check(!proof.Reply(challenge["id"]!.GetValue<string>(), badSignature)); Check(!await task);
        try { proof.ConsumePermit("recovery"); Check(false); } catch (UnauthorizedAccessException) { passed++; }
        task = proof.Verify("game-ftp", CancellationToken.None); challenge = proof.Poll();
        signature = Convert.ToBase64String(rsa.SignData(Convert.FromBase64String(challenge["message"]!.GetValue<string>()), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Check(proof.Reply(challenge["id"]!.GetValue<string>(), signature)); Check(await task);
        try { proof.ConsumePermit("setup"); Check(false); } catch (UnauthorizedAccessException) { passed++; }
        task = proof.Verify("game-ftp", CancellationToken.None); challenge = proof.Poll();
        signature = Convert.ToBase64String(rsa.SignData(Convert.FromBase64String(challenge["message"]!.GetValue<string>()), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Check(proof.Reply(challenge["id"]!.GetValue<string>(), signature)); Check(await task); proof.ConsumePermit("game-ftp"); passed++;
        try { proof.ConsumePermit("game-ftp"); Check(false); } catch (UnauthorizedAccessException) { passed++; }
        using var stream = new MemoryStream(); await Wire.Write(stream, snapshot, CancellationToken.None); stream.Position = 0;
        Check(JsonNode.DeepEquals(snapshot, await Wire.Read(stream, CancellationToken.None)));
        using var oversized = new MemoryStream(new byte[] { 127, 255, 255, 255 });
        try { await Wire.Read(oversized, CancellationToken.None); Check(false); } catch (IOException) { passed++; }
        var pipeName = "FacuSecX.UnitTest." + Guid.NewGuid().ToString("N");
        using var server = new System.IO.Pipes.NamedPipeServerStream(pipeName, System.IO.Pipes.PipeDirection.InOut, 1, System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.Asynchronous);
        using var client = new System.IO.Pipes.NamedPipeClientStream(".", pipeName, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
        var connection = server.WaitForConnectionAsync(); await client.ConnectAsync(3000); await connection;
        string? caller = null; server.RunAsClient(() => { using var identity = System.Security.Principal.WindowsIdentity.GetCurrent(true); caller = identity?.User?.Value; });
        Check(caller == System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value);
        try { PipeIdentity.Verify(client); Check(false); } catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception) { passed++; }
        using (var fields = new SshSetupFields(new JsonObject { ["authMode"] = "password" }))
        {
            Check(fields.Mode.SelectedIndex == 0 && fields.Secret.UseSystemPasswordChar);
            fields.Mode.SelectedIndex = 1; fields.Secret.Text = "synthetic"; fields.Mode.SelectedIndex = 0; Check(fields.Secret.Text == "");
            fields.Fingerprint.Text = "SHA256:" + new string('A',43); fields.Host.Text = "other.example"; Check(fields.Fingerprint.Text == "");
        }
        passed += await RuntimeLifecycleTests.Run();
        passed += await ServiceLifetimeTests.Run().ConfigureAwait(false);
        Console.Out.WriteLine(passed + " native protection checks passed; no real accounts or installation registry entries were modified.");
    }
}
