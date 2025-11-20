SELECT * FROM Storyline

-- Description: DS_Store activity related to .DS_Store files which indicates file/folder accesses.
WHERE "Path" LIKE '%.DS_Store'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC