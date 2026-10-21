using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

public static class ServerMonitorHello {
    [DllImport("combase.dll")] private static extern int RoInitialize(uint type);
    [DllImport("combase.dll")] private static extern void RoUninitialize();
    [DllImport("combase.dll", CharSet=CharSet.Unicode)] private static extern int WindowsCreateString(string text,int length,out IntPtr value);
    [DllImport("combase.dll")] private static extern int WindowsDeleteString(IntPtr value);
    [DllImport("combase.dll")] private static extern int RoGetActivationFactory(IntPtr name,ref Guid iid,out IntPtr factory);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int Availability(IntPtr self,out IntPtr operation);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int Verify(IntPtr self,IntPtr window,IntPtr message,ref Guid iid,out IntPtr operation);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int IntResult(IntPtr self,out int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int VoidCall(IntPtr self);
    private static Delegate Method(IntPtr obj,int slot,Type type) {return Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj),slot*IntPtr.Size),type);}
    private static void Check(int hr) {Marshal.ThrowExceptionForHR(hr);}
    private static IntPtr Factory(string iid) {
        string name="Windows.Security.Credentials.UI.UserConsentVerifier";IntPtr h=IntPtr.Zero,p=IntPtr.Zero;
        try{Check(WindowsCreateString(name,name.Length,out h));Guid g=new Guid(iid);Check(RoGetActivationFactory(h,ref g,out p));return p;}finally{if(h!=IntPtr.Zero)WindowsDeleteString(h);}
    }
    private static int Await(IntPtr operation,Form owner,int timeout) {
        IntPtr info=IntPtr.Zero;Guid iid=new Guid("00000036-0000-0000-c000-000000000046");
        try{
            Check(Marshal.QueryInterface(operation,ref iid,out info));var clock=Stopwatch.StartNew();
            var status=(IntResult)Method(info,7,typeof(IntResult));int state;
            do {
                Application.DoEvents();Check(status(info,out state));if(state!=0)break;
                if(clock.ElapsedMilliseconds>=timeout||(owner!=null&&owner.IsDisposed)){((VoidCall)Method(info,9,typeof(VoidCall)))(info);return 6;}
                Thread.Sleep(30);
            }while(true);
            if(state!=1)return 6;
            int result;Check(((IntResult)Method(operation,8,typeof(IntResult)))(operation,out result));return result;
        }finally{if(info!=IntPtr.Zero){try{((VoidCall)Method(info,10,typeof(VoidCall)))(info);}catch{}Marshal.Release(info);}Marshal.Release(operation);}
    }
    private static int AvailabilityResult(){
        IntPtr factory=Factory("af4f3f91-564c-4ddc-b8b5-973447627c65");
        try{IntPtr op;Check(((Availability)Method(factory,6,typeof(Availability)))(factory,out op));return Await(op,null,10000);}finally{Marshal.Release(factory);}
    }
    public static int Run(bool verify) {return Run(verify,false);}
    public static int Run(bool verify,bool users) {
        int init=RoInitialize(0);Check(init);
        try{
            int available=AvailabilityResult();if(!verify||available!=0)return available;
            IntPtr factory=Factory("39e050c3-4e74-441a-8dc0-b81104df949c"),message=IntPtr.Zero;
            try{
                using(var owner=new Form()) {
                    owner.Text=users?"Server Security Monitor - Usuarios":"Server Security Monitor - Terminal";owner.Width=440;owner.Height=145;owner.StartPosition=FormStartPosition.CenterScreen;owner.FormBorderStyle=FormBorderStyle.FixedDialog;owner.MaximizeBox=false;owner.MinimizeBox=false;owner.TopMost=true;
                    var label=new Label();label.Text=users?"Confirma tu identidad con Windows Hello para administrar usuarios y permisos.":"Confirma tu identidad con Windows Hello para abrir la terminal del servidor.";label.Dock=DockStyle.Fill;label.Padding=new Padding(20);owner.Controls.Add(label);owner.Show();owner.BringToFront();owner.Activate();Application.DoEvents();
                    string text=users?"Autorizar gestión de usuarios de Server Security Monitor":"Autorizar Terminal de Server Security Monitor";Check(WindowsCreateString(text,text.Length,out message));
                    Guid iid=new Guid("fd596ffd-2318-558f-9dbe-d21df43764a5");IntPtr op;
                    Check(((Verify)Method(factory,6,typeof(Verify)))(factory,owner.Handle,message,ref iid,out op));return Await(op,owner,90000);
                }
            }finally{if(message!=IntPtr.Zero)WindowsDeleteString(message);Marshal.Release(factory);}
        }finally{RoUninitialize();}
    }
}
