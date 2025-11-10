SELECT * FROM FSEventsParser

-- Description: DS_Store activity related to .DS_Store files which indicates file/folder accesses.
WHERE "Full Path" LIKE '%.DS_Store'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC