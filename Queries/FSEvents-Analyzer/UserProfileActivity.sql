SELECT * FROM FSEventsParser

-- Description: All file activity that occurs within the user folders Desktop, Documents, Downloads, Pictures, Videos, and Music.
WHERE "Full Path" LIKE 'Users/%Desktop/%' OR "Full Path" LIKE 'Users/%Documents/%' OR "Full Path" LIKE 'Users/%Downloads/%' OR "Full Path" LIKE 'Users/%Music/%' OR "Full Path" LIKE 'Users/%Pictures/%' OR "Full Path" LIKE 'Users/%Videos/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC
-- ORDER BY "Event ID" ASC