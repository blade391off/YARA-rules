import "pe"

rule Fake_Antivirus_Generic {
    meta:
        author = "blade391off"
        description = "Detects generic Fake Antivirus (Scareware) patterns including social engineering strings and system lockdowns"
        date = "2026-08-08"
        version = "1.0"
        severity = "High"

    strings:
        $alert_0 = "Hard drive is corrupted" ascii wide nocase
        $alert_1 = "Infections found" ascii wide nocase
        $alert_2 = "Spyware detected" ascii wide nocase
        $alert_3 = "Critical system leak" ascii wide nocase
        $alert_4 = "System damage" ascii wide nocase
        $alert_5 = "Threats detected" ascii wide nocase

        $pay_0 = "Activate license" ascii wide nocase
        $pay_1 = "Buy full version" ascii wide nocase
        $pay_2 = "Register your copy" ascii wide nocase
        $pay_3 = "Enter activation key" ascii wide nocase
        $pay_4 = "Purchase protection" ascii wide nocase

        $ui_0 = "Scanning system" ascii wide nocase
        $ui_1 = "Scan results" ascii wide nocase
        $ui_2 = "Antivirus Protection" ascii wide nocase
        $ui_3 = "PC Health" ascii wide nocase

        $reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $lock_0 = "DisableTaskMgr" ascii wide
        $lock_1 = "DisableRegistryTools" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and pe.is_dll() == false and
        (
            (3 of ($alert_*) and 2 of ($pay_*)) or
            (2 of ($alert_*) and 2 of ($ui_*) and 1 of ($pay_*)) or
            (
                $reg_path and 1 of ($lock_*) and 
                (2 of ($alert_*) or 1 of ($pay_*))
            )
        )
}
