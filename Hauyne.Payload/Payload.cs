/*
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
 * Mozilla Public License, v. 2.0.
 * 
 */

using System.Runtime.InteropServices;

namespace Hauyne.Payload;

public static class Entrypoint
{
    [UnmanagedCallersOnly]
    public static void Initialize()
    {
        Run();
    }

    static void Run()
    {
        var path = Path.Combine(Path.GetTempPath(), "Hauyne.txt");
        File.WriteAllText(path, $"Payload loaded at {DateTime.Now}");
    }
}