SELECT * FROM Storyline

-- Description: File activity related to email attachments being cached on disk. This can be used to determine names of email attachments
WHERE "Path" LIKE '%Users/%/Attachments/%' OR "Path" LIKE '%Users/%/Library/Containers/com.apple.mail/Data/Mail Downloads/%' OR "Path" LIKE '%mobile/Library/Mail/%/Attachments/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC