SELECT * FROM Storyline

-- Description: Cloud storage activity related to files in the Box folder for the Box.com app.
WHERE "Path" LIKE '%Users/%/Box Sync/%'

-- Sort by timestamp in descending order
ORDER BY CAST(Timestamp as integer) DESC