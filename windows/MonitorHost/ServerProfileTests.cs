using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class ServerProfileTests
{
    internal static int Run()
    {
        int passed=0; void Check(bool valid) { if(!valid)throw new IOException("Server profile isolation test failed."); passed++; }
        JsonObject Settings(string host) => new() { ["host"]=host,["port"]=22,["user"]="debian",["mode"]="password",["secret"]="synthetic-ssh-only",["fingerprint"]="SHA256:"+new string('A',43) };
        JsonObject Profile(string host,string id) => new() { ["id"]=id,["label"]=host,["settings"]=Settings(host),["legacy"]=false,["identity"]=new string('f',32) };
        JsonObject? encrypted=null;
        var profiles=new ServerProfiles(()=>encrypted?.DeepClone().AsObject(),value=>encrypted=value.DeepClone().AsObject());
        Check(profiles.Active()==null && profiles.Listing()["profiles"]!.AsArray().Count==0);
        JsonObject a=Profile("server-a.example",new string('a',32)),b=Profile("server-b.example",new string('b',32));
        var candidate=profiles.WithActive(a); Check(encrypted==null); // Preparing never saves.
        profiles.Save(candidate); Check(profiles.Active()!["id"]!.GetValue<string>()==new string('a',32));
        profiles.Save(profiles.WithActive(b)); Check(profiles.Listing()["profiles"]!.AsArray().Count==2);
        Check(profiles.Active()!["id"]!.GetValue<string>()==new string('b',32));
        Check(profiles.Get(new string('a',32))["settings"]!["host"]!.GetValue<string>()=="server-a.example");
        Check(!profiles.Listing().ToJsonString().Contains("synthetic-ssh-only") && !profiles.Listing().ToJsonString().Contains("privateKey"));
        profiles.Save(profiles.WithActive(a)); Check(profiles.Active()!["id"]!.GetValue<string>()==new string('a',32));
        Check(!profiles.Listing().ToJsonString().Contains("accounts") && !profiles.Listing().ToJsonString().Contains("passwordHash"));
        encrypted!["active"]=new string('c',32); try { profiles.Load();Check(false); } catch(IOException){passed++;} encrypted["active"]=new string('a',32);
        encrypted["profiles"]!.AsArray().Add(a.DeepClone());try { profiles.Load();Check(false); } catch(IOException){passed++;} encrypted["profiles"]!.AsArray().RemoveAt(2);
        var loaded=profiles.Get(new string('a',32)); loaded["settings"]!["secret"]="mutated"; Check(profiles.Get(new string('a',32))["settings"]!["secret"]!.GetValue<string>()=="synthetic-ssh-only");
        using var rsa=RSA.Create(2048); var publicKey=Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()); var now=DateTime.UtcNow;
        var proof=new ServerSelectionProof(()=>publicKey,()=>"PS256",()=>now);
        string Sign(JsonObject request) => Convert.ToBase64String(rsa.SignData(Convert.FromBase64String(request["message"]!.GetValue<string>()),HashAlgorithmName.SHA256,RSASignaturePadding.Pss));
        var request=proof.Issue("synthetic-install",a); proof.Consume(request["token"]!.GetValue<string>(),Sign(request));passed++;
        try{proof.Consume(request["token"]!.GetValue<string>(),Sign(request));Check(false);}catch(UnauthorizedAccessException){passed++;}
        request=proof.Issue("synthetic-install",a); now=now.AddMinutes(3);try{proof.Consume(request["token"]!.GetValue<string>(),Sign(request));Check(false);}catch(UnauthorizedAccessException){passed++;}
        request=proof.Issue("synthetic-install",a);var newer=proof.Issue("synthetic-install",b);try{proof.Consume(request["token"]!.GetValue<string>(),Sign(request));Check(false);}catch(UnauthorizedAccessException){passed++;}
        request=proof.Issue("synthetic-install",a);using var other=RSA.Create(2048); string wrong=Convert.ToBase64String(other.SignData(Convert.FromBase64String(request["message"]!.GetValue<string>()),HashAlgorithmName.SHA256,RSASignaturePadding.Pss));
        try{proof.Consume(request["token"]!.GetValue<string>(),wrong);Check(false);}catch(UnauthorizedAccessException){passed++;}
        Check(ServerProfiles.Id(Settings("server-a.example"))!=ServerProfiles.Id(Settings("server-b.example")));
        try{ServerProfiles.Label("bad\nlabel");Check(false);}catch(IOException){passed++;}
        try{ServerProfiles.ValidateSettings(new JsonObject{["host"]="a.example",["port"]=22,["user"]="root",["mode"]="password",["secret"]="",["fingerprint"]="SHA256:"+new string('A',43)});Check(false);}catch(IOException){passed++;}
        return passed;
    }
}
