SELECT * FROM FSEventsParser

-- Outlook Temp Folder --> Outlook Temp Files
-- Location: ~/Library/Caches/TemporaryItems/Outlook Temp/
-- Description: Previously opened attachments and other cached files are stored in this temporary location.
WHERE "Full Path" like '%Outlook Temp/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC