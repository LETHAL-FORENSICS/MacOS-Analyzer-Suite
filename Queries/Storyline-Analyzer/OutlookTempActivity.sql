SELECT * FROM Storyline

-- Outlook Temp Folder --> Outlook Temp Files
-- Location: ~/Library/Caches/TemporaryItems/Outlook Temp/
-- Description: Previously opened attachments and other cached files are stored in this temporary location.
WHERE "Path" like '%Outlook Temp/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC