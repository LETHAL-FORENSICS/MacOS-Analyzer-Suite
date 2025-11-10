SELECT * FROM FSEventsParser

-- Description: Cloud storage activity related to files in the Dropbox folder for the Dropbox app.
WHERE "Full Path" LIKE '%Users/%/Dropbox/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC