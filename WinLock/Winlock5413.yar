import "pe"
import "hash"

rule WinLocker_WinLockLoader
{
    meta:
        author = "blade391off"
        date = "2026-08-18"
        version = "1.1"
        description = "Detect WinLockLoader"
        family = "WinLocker"
        category = "Loader / ScreenLocker"
        threat_level = "critical"
        confidence = "high"
        reference = "ANY.RUN task d7e8a65b-e222-4c74-bf7c-bcc3c402dd9e"

    strings:
        $name_1 = "WinLock.exe" ascii wide nocase
        $name_2 = "lc.exe" ascii wide nocase
        $name_3 = "AWindowsService.exe" ascii wide nocase
        $name_4 = "taskhost.exe" ascii wide nocase

        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg_runonce = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $reg_winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $reg_shell = "Shell" ascii wide nocase
        $reg_runmru = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" ascii wide nocase

        $autorun_1 = "WIN32_1" ascii wide nocase
        $autorun_2 = "WIN32_2" ascii wide nocase
        $autorun_3 = "System3264Wow" ascii wide nocase
        $autorun_4 = "OneDrive10293" ascii wide nocase
        $autorun_5 = "WINDOWS" ascii wide nocase

        $locker_1 = "info-Locker.txt" ascii wide nocase
        $locker_2 = "$unlocker_id.ux-cryptobytes" ascii wide nocase
        $locker_3 = "Ooops!" ascii wide nocase
        $locker_4 = "Your files are encrypted" ascii wide nocase
        $locker_5 = "Telegram" ascii wide nocase
        $locker_7 = "YOU ARE HACKED!" ascii wide nocase
        $locker_8 = "HAHAHAHAHAHAHA" ascii wide nocase
        $locker_9 = "BIBORAN.com" ascii wide nocase

        $cmd = "cmd.exe" ascii wide nocase
        $attrib = "attrib.exe" ascii wide nocase
        $taskkill = "taskkill.exe" ascii wide nocase

        $attr_1 = "+h" ascii wide nocase
        $attr_2 = "+s" ascii wide nocase
        $attr_3 = "+r" ascii wide nocase
        $attr_4 = "+i" ascii wide nocase

        $path_1 = "%userprofile%\\desktop" ascii wide nocase
        $path_2 = "%userprofile%\\downloads" ascii wide nocase
        $path_3 = "%userprofile%\\documents" ascii wide nocase
        $path_4 = "%systemdrive%\\Users\\Public\\Desktop" ascii wide nocase
        $path_5 = "\\AppData\\Local\\Temp\\" ascii wide nocase

        $dotnet = "mscoree.dll" ascii wide nocase
        $mono = "Mono/.Net" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize <= 5MB
        and
        (
            hash.sha256(0, filesize) == "86453C1A381C4F48999307B1A4890C22322971004D5714729DF80533684A03D2"
            or
            (
                pe.is_pe
                and pe.number_of_sections <= 5
                and
                (
                    $dotnet
                    or pe.imports("mscoree.dll", "_CorExeMain")
                    or pe.imports("mscoree.dll", "_CorExeMainCRTStartup")
                )
                and
                (
                    (3 of ($name_*) and 2 of ($autorun_*))
                    or (2 of ($reg_*) and 2 of ($autorun_*) and 1 of ($name_*))
                    or (2 of ($locker_*) and $cmd and $attrib and 2 of ($attr_*))
                    or ($reg_winlogon and $reg_shell and $reg_runonce and $cmd)
                    or ($locker_1 and $attrib and $taskkill)
                    or 1 of ($path_*)
                )
            )
        )
}
