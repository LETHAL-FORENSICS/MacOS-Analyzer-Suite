SELECT * FROM Storyline

-- Description: Activity related to files synced to iCloud. These events can reveal the names of files that have been synced to iCloud from other devices.
WHERE "Path" LIKE '%.iCloud' OR "Path" LIKE '%Mobile Documents_com_apple_CloudDocs%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC