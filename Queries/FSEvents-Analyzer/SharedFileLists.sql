SELECT * FROM FSEventsParser

-- Descriton: Activity related to Shared File List files (.sfl and .sfl2).
WHERE "Full Path" LIKE '%.sfl' OR "Full Path" LIKE '%.sfl2'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC