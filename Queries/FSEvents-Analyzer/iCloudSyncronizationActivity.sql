SELECT * FROM FSEventsParser

-- Description: Activity related to files synced to iCloud. These events can reveal the names of files that have been synced to iCloud from other devices.
WHERE "Full Path" LIKE '%.iCloud' OR "Full Path" LIKE '%Mobile Documents_com_apple_CloudDocs%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC