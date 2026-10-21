using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class GameFtpScopeTests
{
    internal static int Run()
    {
        int count=0;
        void Check(bool value) { if(!value)throw new IOException("FTP server profile scope regression.");count++; }
        const string host="fixture.example",user="debian",pin="SHA256:synthetic";
        string a=new('a',32),b=new('b',32);
        string Expected(params string[] fields)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n",fields)))).ToLowerInvariant();
        JsonObject Profile(string id,bool legacy)=>new() { ["id"]=id,["legacy"]=legacy,["settings"]=new JsonObject { ["host"]=host,["port"]=22,["user"]=user,["fingerprint"]=pin } };
        Check(GameFtpSecrets.ScopeFor(host,22,user,pin)==Expected(host,"22",user,pin));
        Check(GameFtpSecrets.ScopeForProfile(Profile(a,true))==Expected(host,"22",user,pin));
        Check(GameFtpSecrets.ScopeForProfile(Profile(a,false))==Expected(host,"22",user,pin,a));
        Check(GameFtpSecrets.ScopeForProfile(Profile(a,false))!=GameFtpSecrets.ScopeForProfile(Profile(b,false)));
        Check(GameFtpSecrets.ScopeForProfile(Profile(a,false))!=GameFtpSecrets.ScopeForProfile(Profile(a,true)));
        Check(GameFtpSecrets.ScopeForProfile(Profile(a,false))==GameFtpSecrets.ScopeFor(host,22,user,pin,a));
        Check(GameFtpSecrets.ScopeFor(host,2222,user,pin,a)!=GameFtpSecrets.ScopeFor(host,22,user,pin,a));
        Check(GameFtpSecrets.ScopeFor(host,22,"other",pin,a)!=GameFtpSecrets.ScopeFor(host,22,user,pin,a));
        Check(GameFtpSecrets.ScopeFor(host,22,user,"changed",a)!=GameFtpSecrets.ScopeFor(host,22,user,pin,a));
        foreach(var id in new[]{"../invalid",new string('a',31),new string('A',32)}) {
            try { GameFtpSecrets.ScopeForProfile(Profile(id,false));throw new InvalidOperationException("Invalid profile accepted."); }
            catch(IOException){count++;}
        }
        var entry=new JsonObject { ["scope"]=new string('a',64),["id"]=new string('b',32),["username"]="sampftp",["password"]=new string('s',32) };
        var snapshot=new JsonObject { ["entries"]=new JsonArray(entry) };
        var original=snapshot.DeepClone();
        for(int iteration=0;iteration<3;iteration++) {
            var entries=GameFtpSecrets.ReadEntries(snapshot);
            Check(entries.Parent==null && entries.Count==1);
            entries.RemoveAt(0);entries.Add(entry.DeepClone());
            snapshot=new JsonObject { ["entries"]=entries };
            Check(JsonNode.DeepEquals(snapshot,original));
        }
        var cleared=GameFtpSecrets.ReadEntries(snapshot);cleared.Clear();
        var empty=new JsonObject { ["entries"]=cleared };
        Check(empty["entries"]!.AsArray().Count==0 && snapshot["entries"]!.AsArray().Count==1);
        return count;
    }
}
