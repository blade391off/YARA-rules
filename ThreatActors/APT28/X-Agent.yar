import "hash"

rule APT28_XAgent
{
    meta:
        description = "Detect X-Agent"
        author = "blade391off"
        date = "2026-08-31"
        category = "apt"
        threat_actor = "APT28"

    strings:
        $name1 = "X-Agent" ascii nocase
        $name2 = "XAgent" ascii nocase
        $name3 = "Chopstick" ascii nocase
        $path1 = "splm.dat" ascii nocase
        $path2 = "GameExplorer.dll" ascii nocase
        $path3 = "com.apple.updates.plist" ascii nocase
        $reg1 = "CurrentVersion\\Run\\svchost" ascii nocase
        $reg2 = "UserInitMprLogonScript" ascii nocase
        $uri1 = "/results.php?id=" ascii nocase
        $uri2 = "/index.asmx" ascii nocase
        $uri3 = "/watch?v=" ascii nocase
        $uri4 = "/search?q=" ascii nocase
        $domain1 = "apple-iclouds.com" ascii nocase
        $domain2 = "mx-apple.org" ascii nocase
        $domain3 = "account-google-security.com" ascii nocase
        $domain4 = "corpsg-mail.com" ascii nocase
        $domain5 = "post-office-service.com" ascii nocase
        $ip1 = "185.216.140.38" ascii
        $ip2 = "194.61.121.42" ascii

    condition:
        hash.sha256(0, filesize) in (
            "255d64ff18a16db8a2cf3df09e1e2d4d81237ebdc138676b701c34d0b11df052",
            "90ac7bf6e0b76245296e194bc1bd8a6388d013b7e11be906ae0352ff22c3f472",
            "7823f669e462bf405e305e55e090df453147ba84bc6c06838384f50125860d5b",
            "e547214fbc9df451f2d659779df30058b7654d24f0c62b9a76d49ca71a620d44",
            "c6e8e8b0b56b3e8e19db9a35e80d463b2f9241b3156fa301d0bc881ba08d4b31",
            "3a6b8e217d890bfaee013d567c9cde2f871340b1ee06efda156a29774debcde1",
            "f8352b217e056ba83cd3dffc71a3962b405e3ecbc3970b8a1c97a5f6e80b2a3a"
        ) or
        hash.md5(0, filesize) in (
            "13d31eb49989f6da409403d6d0ffbe0c",
            "61159cc4cd1827b508f7db08e16279f0"
        ) or
        (
            2 of ($name*) and
            2 of ($path*) 
        ) or
        (
            1 of ($name*) and
            2 of ($reg*) 
        ) or
        (
            1 of ($name*) and
            2 of ($uri*)
        )
}
