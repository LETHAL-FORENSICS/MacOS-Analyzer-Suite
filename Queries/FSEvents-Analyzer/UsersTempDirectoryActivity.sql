SELECT * FROM FSEventsParser

-- Temp Directory (user-specific) --> won't be cleared out on reboot
-- Note: /var/tmp (Symlink) ==> /private/var/tmp
-- Description: FIle activity that occurs within the user's temp directory.
WHERE "Full Path" like '%private/var/tmp%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC