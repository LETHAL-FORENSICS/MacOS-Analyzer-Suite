SELECT * FROM Storyline

-- Temp Directory (user-specific) --> won't be cleared out on reboot
-- Note: /var/tmp (Symlink) ==> /private/var/tmp
-- Description: FIle activity that occurs within the user's temp directory.
WHERE "Path" like '%private/var/tmp%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC