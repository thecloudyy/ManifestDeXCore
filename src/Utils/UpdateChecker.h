#pragma once

namespace UpdateChecker {

    // Fetches the expected DLL hashes from the ManifestDex API and compares
    // them against the files on disk.  If any hash mismatches, a MessageBox
    // is shown to inform the user that an update is available.
    //
    // Must be called once from the InitThread worker (NOT from DllMain).
    // If the network request fails for any reason the function returns silently.
    void Check(const char* steamInstallPath);

    // Runs pending Steam VGUI work on SteamUI's frame thread.
    void PumpSteamUi();

} // namespace UpdateChecker
