SELECT * FROM Storyline

-- Description: Cloud storage activity related to files in the Dropbox folder for the Dropbox app.
WHERE "Path" LIKE '%Users/%/Dropbox/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC