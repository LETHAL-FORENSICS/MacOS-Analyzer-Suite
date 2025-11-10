SELECT * FROM FSEventsParser

-- Temp Directory (system-wide) --> will be cleared after reboot
-- Note: /tmp (Symlink) ==> /private/tmp
-- Description: Malware often stores data in this directory before exfiltration, AirDrop files can be found in this directory (next to Downloads directory)
WHERE "Full Path" like '%private/tmp%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC