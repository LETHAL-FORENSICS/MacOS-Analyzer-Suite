SELECT * FROM Storyline

-- Temp Directory (system-wide) --> will be cleared after reboot
-- Note: /tmp (Symlink) ==> /private/tmp
-- Description: Malware often stores data in this directory before exfiltration, AirDrop files can be found in this directory (next to Downloads directory)
WHERE "Path" like '%private/tmp%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC