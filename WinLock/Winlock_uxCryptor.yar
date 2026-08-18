import "pe"
import "hash"

rule WinLocker_Winlock_uxCryptor
{
    meta:
        author = "blade391off"
        date = "2026-08-18"
        version = "1.1"
        description = "Detect UxCryptor"
        family = "WinLocker"
        category = "Ransomware / ScreenLocker"
        threat_level = "critical"
        confidence = "high"
        reference = "ANY.RUN task 99bf97f2-6c23-4721-9e8c-8d722b74e7ac"

    strings:
        $ux_cryptor_1 = "ux-cryptor.exe" ascii wide nocase
        $ux_cryptor_2 = "crypt0rsx.exe" ascii wide nocase
        $ux_cryptor_3 = "AWindowsService.exe" ascii wide nocase
        $ux_cryptor_4 = "windowsx-c.exe" ascii wide nocase
        $ux_cryptor_5 = "_default64.exe" ascii wide nocase
        $ux_cryptor_6 = "WIN32_1" ascii wide nocase
        $ux_cryptor_7 = "WIN32_2" ascii wide nocase
        $ux_cryptor_8 = "WIN32_3" ascii wide nocase
        $ux_cryptor_9 = "WIN32_4" ascii wide nocase
        $ux_cryptor_10 = "WIN32_5" ascii wide nocase
        $ux_cryptor_11 = "WIN32_6" ascii wide nocase
        $ux_cryptor_12 = "WIN32_7" ascii wide nocase
        $ux_cryptor_13 = "WIN32_8" ascii wide nocase

        $locker_file = "info-Locker.txt" ascii wide nocase
        $unlocker_file = "$unlocker_id.ux-cryptobytes" ascii wide nocase
        $encrypted_msg_1 = "Your files are encrypted" ascii wide nocase
        $encrypted_msg_2 = "Ooops!" ascii wide nocase
        $encrypted_msg_3 = "Введите код разблокировки" ascii wide
        $encrypted_msg_4 = "Ваши файлы зашифрованы" utf8 wide

        $run_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run_wininstaller = "WindowsInstaller" ascii wide nocase
        $run_edgeupdate = "MSEdgeUpdateX" ascii wide nocase

        $cmd = "cmd.exe" ascii wide nocase
        $attrib = "attrib" ascii wide nocase
        $taskkill = "taskkill.exe" ascii wide nocase
        $attrib_hide = "+h" ascii wide nocase
        $attrib_system = "+s" ascii wide nocase
        $attrib_readonly = "+r" ascii wide nocase
        $attrib_index = "+i" ascii wide nocase

        $desktop = "%userprofile%\\desktop" ascii wide nocase
        $downloads = "%userprofile%\\downloads" ascii wide nocase
        $documents = "%userprofile%\\documents" ascii wide nocase
        $public = "%systemdrive%\\Users\\Public\\Desktop" ascii wide nocase

        $mscoree = "mscoree.dll" ascii wide nocase
        $lc_exe = "lc.exe" ascii wide nocase

    condition:
        (
            uint16(0) == 0x5A4D
            and filesize <= 20MB
            and
            (
                hash.sha256(0, filesize) == "D3F47CD85C525A0C3ED855949BF27023C27B24C51D388166D72D4FA8CAE4C2F5"
                or hash.sha256(0, filesize) == "593E60CC30AE0789448547195AF77F550387F6648D45847EA244DD0DD7ABF03D"
                or hash.sha256(0, filesize) == "EAD58C483CB20BCD57464F8A4929079539D634F469B213054BF737D227C026DC"
                or hash.sha256(0, filesize) == "7587E29919A56B6F94675E49208E1AE908BCAB09363734D846502C3B4AD54326"
                or hash.sha256(0, filesize) == "2A0AA0763FDEF9C38C5DD4D50703F0C7E27F4903C139804EC75E55F8388139AE"
                or hash.sha256(0, filesize) == "9B2C8B8C4CEC301C4303F58CA4E8B261D516F10FEB24573B092DFCCC263BAEA4"
                or hash.sha256(0, filesize) == "43EEF3B68EBAAB3EFBE15EB3046281E380AA78003A0EDA8757A9E44F6A59EC7F"
                or hash.sha256(0, filesize) == "E17CD94C08FC0E001A49F43A0801CEA4625FB9AEE211B6DFEBEBEC446C21F460"
                or hash.sha256(0, filesize) == "6A24BF4AE4359CB9C5CBE6A0AD3FE150DD7380313DC31587C4C5E2564C50274A"
                or hash.sha256(0, filesize) == "CEC9DF2D0292931147C824203AC9A594088E91CA04EA8CC128B7DC9DC42AE805"
                or hash.sha256(0, filesize) == "E49DC5724ADEE8F30FF25F0BB587E318F4F3D4C0F051866B437C831E7253B988"
            )
        )
        or
        (
            uint16(0) == 0x5A4D
            and pe.is_pe
            and filesize <= 20MB
            and
            (
                $mscoree
                or pe.number_of_sections <= 5
            )
            and
            (
                ($run_key and ($run_wininstaller or $run_edgeupdate or 2 of ($ux_cryptor_*)))
                or (2 of ($locker_file, $unlocker_file, $encrypted_msg_*) and ($cmd or $attrib or $taskkill))
                or (3 of ($ux_cryptor_*) and ($run_key or $cmd or $attrib))
                or ($cmd and $attrib and 2 of ($locker_file, $encrypted_msg_*))
            )
        )
}
