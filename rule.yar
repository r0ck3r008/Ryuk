rule practical3_Ryuk {
	meta:
		description = "Detect Practical3.exe Ryuk Ransomware"
		author = "Naman Arora"
		date = "2021-04-13"
		hash = "98ece6bcafa296326654db862140520afc19cfa0b4a76a5950deedb2618097ab"
	strings:
		$pdb = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects From Ryuk\\ConsoleApplication54\\x64\\Release\\ConsoleApplication54.pdb" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and $pdb
}
