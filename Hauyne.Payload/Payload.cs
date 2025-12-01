using System.Runtime.InteropServices;

namespace Hauyne.Payload;

public static class Entrypoint
{
    [UnmanagedCallersOnly]
    public static void Initialize()
    {
        new Thread(Run) { IsBackground = true }.Start();
    }

    static void Run()
    {
        File.WriteAllText(@"C:\temp\Hauyne.txt", $"Payload loaded at {DateTime.Now}");
    }
}