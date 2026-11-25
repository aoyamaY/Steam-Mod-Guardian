using Mono.Cecil;
using Mono.Cecil.Cil;
using System.Text;
namespace Guardian.Core;

// Bounded, intraprocedural abstract interpretation; never invokes sample code.
public static class LocalFlow
{
    private readonly record struct V(bool Net=false,string? Constant=null,bool Bytes=false,bool File=false)
    {
        public static V Merge(V a,V b)=>new(a.Net||b.Net,a.Constant==b.Constant&&a.Bytes==b.Bytes?a.Constant:null,a.Bytes&&b.Bytes,a.File&&b.File);
    }
    private sealed record State(V[] Locals,List<V> Stack);
    public sealed record Result(List<Evidence> Evidence,List<string> Hosts,bool Disk,bool Load,bool Limited);
    public static Result Inspect(MethodDefinition method,CancellationToken ct=default)
    {
        var ev=new List<Evidence>();var hosts=new HashSet<string>(StringComparer.OrdinalIgnoreCase);bool disk=false,load=false,limited=false;
        if(!method.HasBody||method.Body.Instructions.Count==0)return new(ev,[],false,false,false);
        var code=method.Body.Instructions;
        if(!code.Any(i=>i.Operand is MethodReference m&&(IsSource(m)||m.Name is "FromBase64String" or "Concat")))return new(ev,[],false,false,false);
        if(code.Count>3000||method.Body.Variables.Count>256||method.Body.ExceptionHandlers.Count>0)return new(ev,[],false,false,true);
        var indices=code.Select((i,n)=>(i,n)).ToDictionary(x=>x.i,x=>x.n);
        var states=new Dictionary<int,State>();var q=new Queue<int>();int steps=0;
        void Put(int idx,State s){if(idx<0||idx>=code.Count)return;if(!states.TryGetValue(idx,out var old)){states[idx]=new((V[])s.Locals.Clone(),new(s.Stack));q.Enqueue(idx);return;}if(old.Stack.Count!=s.Stack.Count){limited=true;return;}bool changed=false;for(int j=0;j<old.Locals.Length;j++){var v=V.Merge(old.Locals[j],s.Locals[j]);if(v!=old.Locals[j]){old.Locals[j]=v;changed=true;}}for(int j=0;j<old.Stack.Count;j++){var v=V.Merge(old.Stack[j],s.Stack[j]);if(v!=old.Stack[j]){old.Stack[j]=v;changed=true;}}if(changed)q.Enqueue(idx);}
        void Evidence(string rule,Risk risk,Instruction i,string detail){if(ev.Count<30&&!ev.Any(e=>e.Rule==rule&&e.Detail==detail))ev.Add(new(rule,risk,method.FullName,$"IL_{i.Offset:X4} {detail}（有限方法内数据流，非运行时证明）"));}
        void Recover(string s,Instruction i){if(s.Length>4096||hosts.Count>=32)return;foreach(var h in DeepInspection.Hosts(Encoding.UTF8.GetBytes(s),ct).Take(32))if(hosts.Add(h))Evidence("静态常量还原域名",Risk.Review,i,h);}
        Put(0,new(new V[method.Body.Variables.Count],[]));
        while(q.Count>0){ct.ThrowIfCancellationRequested();if(++steps>12000){limited=true;break;}int n=q.Dequeue();var old=states[n];var s=new State((V[])old.Locals.Clone(),new(old.Stack));var i=code[n];var op=i.OpCode.Code;
            V Pop(){if(s.Stack.Count==0)throw new InvalidDataException("stack");var v=s.Stack[^1];s.Stack.RemoveAt(s.Stack.Count-1);return v;}
            void Push(V v){if(s.Stack.Count>=128)throw new InvalidDataException("stack limit");s.Stack.Add(v);}
            try{
                if(op==Code.Ldstr)Push(new(Constant:i.Operand is string str&&str.Length<=4096?str:null));
                else if(op is Code.Ldloc or Code.Ldloc_S or Code.Ldloc_0 or Code.Ldloc_1 or Code.Ldloc_2 or Code.Ldloc_3)Push(s.Locals[Local(i)]);
                else if(op is Code.Stloc or Code.Stloc_S or Code.Stloc_0 or Code.Stloc_1 or Code.Stloc_2 or Code.Stloc_3)s.Locals[Local(i)]=Pop();
                else if(op==Code.Dup){var v=Pop();Push(v);Push(v);}
                else if(op==Code.Pop)Pop();
                else if((op is Code.Call or Code.Callvirt or Code.Newobj) && i.Operand is MethodReference){var m=(MethodReference)i.Operand;var args=new V[m.Parameters.Count];for(int j=args.Length-1;j>=0;j--)args[j]=Pop();var self=m.HasThis&&op!=Code.Newobj?Pop():default;string type=m.DeclaringType.FullName,name=m.Name;var v=new V();
                    if(IsSource(m))v=new(Net:true);
                    else if((name is "GetAwaiter" or "GetResult" or "ConfigureAwait" or "get_Result")&&(type.StartsWith("System.Threading.Tasks.")||type.StartsWith("System.Runtime.CompilerServices.")))v=new(Net:self.Net);
                    else if(type=="System.IO.FileStream"&&op==Code.Newobj)v=new(File:true);
                    else if(type=="System.IO.File"&&(name is "Create" or "OpenWrite"))v=new(File:true);
                    else if(type=="System.String"&&name=="Concat"&&args.Length is >=2 and <=4&&args.All(a=>a.Constant!=null&&!a.Bytes)){string joined=string.Concat(args.Select(a=>a.Constant));if(joined.Length<=4096){v=new(Constant:joined);Recover(joined,i);}}
                    else if(type=="System.Convert"&&name=="FromBase64String"&&args.Length==1&&args[0].Constant is string b64&&!args[0].Bytes){try{var b=Convert.FromBase64String(b64);if(b.Length<=4096){v=new(Constant:Convert.ToBase64String(b),Bytes:true);Recover(Encoding.UTF8.GetString(b),i);}}catch(FormatException){}}
                    else if(type.StartsWith("System.Text.")&&name=="GetString"&&args.Length==1){v=new(Net:args[0].Net);if(args[0].Bytes&&args[0].Constant is string b){var str=Encoding.UTF8.GetString(Convert.FromBase64String(b));v=new(args[0].Net,str);Recover(str,i);}}
                    if((type=="System.IO.File"&&(name is "WriteAllBytes" or "WriteAllBytesAsync" or "WriteAllText" or "WriteAllTextAsync" or "AppendAllText" or "AppendAllTextAsync")&&args.Length>=2&&args[1].Net)||(type=="System.IO.FileStream"&&name.StartsWith("Write")&&args.Length>0&&args[0].Net)||(type=="System.IO.Stream"&&name.StartsWith("CopyTo")&&self.Net&&args.Length>0&&args[0].File)) {disk=true;Evidence("数据流：网络数据到文件写入",Risk.Critical,i,type+"::"+name);}
                    if((type=="System.Reflection.Assembly"&&name=="Load"||type=="System.AppDomain"&&name=="Load")&&args.Length>0&&args[0].Net){load=true;Evidence("数据流：网络数据到程序集加载",Risk.Critical,i,type+"::"+name);}
                    if(op==Code.Newobj||m.ReturnType.MetadataType!=MetadataType.Void)Push(v);
                }
                else if(op is Code.Ret or Code.Throw or Code.Rethrow or Code.Endfinally or Code.Endfilter)continue;
                else {string pop=i.OpCode.StackBehaviourPop.ToString(),push=i.OpCode.StackBehaviourPush.ToString();if(pop=="PopAll")s.Stack.Clear();else if(pop=="Varpop"||push=="Varpush"){limited=true;continue;}else if(pop!="Pop0")foreach(var _ in pop.Split('_'))Pop();if(push!="Push0")foreach(var _ in push.Split('_'))Push(default);}
                if(i.OpCode.FlowControl==FlowControl.Branch){if(i.Operand is Instruction dest)Put(indices[dest],s);else limited=true;}
                else if(i.OpCode.FlowControl==FlowControl.Cond_Branch){if(i.Operand is Instruction branchTarget)Put(indices[branchTarget],s);else if(i.Operand is Instruction[] dests)foreach(var d in dests)Put(indices[d],s);Put(n+1,s);}
                else if(i.OpCode.FlowControl is not (FlowControl.Return or FlowControl.Throw))Put(n+1,s);
            }catch(InvalidDataException){limited=true;}catch(IndexOutOfRangeException){limited=true;}
        }
        return new(ev,hosts.ToList(),disk,load,limited);
    }
    private static bool IsSource(MethodReference m){string t=m.DeclaringType.FullName,n=m.Name;return t=="System.Net.WebClient"&&(n.StartsWith("DownloadData")||n.StartsWith("DownloadString")||n.StartsWith("OpenRead"))||t=="System.Net.Http.HttpClient"&&(n.StartsWith("GetByteArray")||n.StartsWith("GetString")||n.StartsWith("GetStream"))||t=="System.Net.Http.HttpContent"&&(n.StartsWith("ReadAsByteArray")||n.StartsWith("ReadAsString")||n.StartsWith("ReadAsStream"));}
    private static int Local(Instruction i)=>i.OpCode.Code switch{Code.Ldloc_0 or Code.Stloc_0=>0,Code.Ldloc_1 or Code.Stloc_1=>1,Code.Ldloc_2 or Code.Stloc_2=>2,Code.Ldloc_3 or Code.Stloc_3=>3,_=>((VariableDefinition)i.Operand).Index};
}
