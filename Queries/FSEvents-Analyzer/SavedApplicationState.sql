SELECT * FROM FSEventsParser

-- Description: Indication that a window was open and the application state was saved.
WHERE "Full Path" LIKE '%/Saved Application State/%windows.plist'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC