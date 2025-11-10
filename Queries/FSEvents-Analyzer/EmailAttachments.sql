SELECT * FROM FSEventsParser

-- Description: File activity related to email attachments being cached on disk. This can be used to determine names of email attachments
WHERE "Full Path" LIKE '%Users/%/Attachments/%' OR "Full Path" LIKE '%Users/%/Library/Containers/com.apple.mail/Data/Mail Downloads/%' OR "Full Path" LIKE '%mobile/Library/Mail/%/Attachments/%'

-- Sort by event id in ascending order (starting with the earliest date and ending with the most recent one)
ORDER BY CAST("Event ID" as integer) ASC