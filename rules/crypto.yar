// Small starter rule set. Extend with public rules (e.g. Yara-Rules/rules crypto_signatures.yar).

rule ChaCha_Salsa_Sigma
{
    strings:
        $sigma = "expand 32-byte k"
        $tau = "expand 16-byte k"
    condition:
        any of them
}

rule AES_Sbox
{
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $inv = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
    condition:
        any of them
}

rule Ransom_Note_Strings
{
    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = ".onion" nocase
        $d = "vssadmin delete shadows" nocase
    condition:
        2 of them
}
